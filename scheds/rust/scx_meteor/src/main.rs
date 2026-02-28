// SPDX-License-Identifier: GPL-2.0
//
// scx_meteor_v2 — sched_ext scheduler for Intel Meteor Lake / Core Ultra 9 185H
//
// Three-tier core topology:
//   LP E-cores  (SoC tile)     — Low Power Island, no L3 cache
//   E-cores     (Compute tile) — Crestmont, shared L3
//   P-cores     (Compute tile) — Redwood Cove, shared L3
//
// Strategy: LP-first, burst-escalate to E/P, drain-back to LP.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;

use std::collections::HashMap;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::{
    scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity, uei_exited, uei_report,
    CoreType, NR_CPU_IDS,
};
use scx_utils::{Topology, UserExitInfo};
use serde::{Deserialize, Serialize};
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_meteor";
const TIER_LP_U8: u8 = 0;
const TIER_E_U8: u8 = 1;
const TIER_P_U8: u8 = 2;
const TIER_RULE_FORCE_U8: u8 = 0;
const TIER_RULE_MIN_U8: u8 = 1;

/// Frequency threshold for Meteor Lake core-type detection (kHz).
/// CPUs with max_freq > P_FREQ_THRESH → P-core (Redwood Cove)
/// CPUs with max_freq > E_FREQ_THRESH (and ≤ P) → E-core (Crestmont, Compute)
/// CPUs with max_freq ≤ E_FREQ_THRESH → LP E-core (Crestmont, SoC tile)
const P_FREQ_THRESH_KHZ: usize = 4_000_000; // 4.0 GHz
const E_FREQ_THRESH_KHZ: usize = 3_000_000; // 3.0 GHz

/// Detected three-tier core topology.
#[derive(Debug)]
struct CoreTiers {
    lp_cpus: Vec<u32>, // LP E-core CPU IDs (SoC tile, Low Power Island)
    e_cpus: Vec<u32>,  // E-core CPU IDs (Compute tile, Crestmont)
    p_cpus: Vec<u32>,  // P-core CPU IDs (Compute tile, Redwood Cove)
}

/// Persistent per-process profile stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcProfile {
    tier: u8,
    confidence: u8,
    #[serde(default)]
    vol_ctx_per_sec: u32,
    #[serde(default, alias = "wakeup_freq")]
    wakeups_per_sec: u32,
    #[serde(default)]
    observations: u32,
    avg_burst_ns: u64,
    #[serde(default)]
    avg_sleep_ns: u64,
    #[serde(default)]
    total_runtime_ns: u64,
}

#[derive(Debug, Clone)]
struct HfiPaths {
    perf: PathBuf,
    eff: PathBuf,
}

/// Read cpuinfo_max_freq (kHz) for a CPU from sysfs.
fn read_max_freq_khz(cpu: usize) -> Option<usize> {
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/cpuinfo_max_freq",
        cpu
    );
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
}

fn read_u8_from_file(path: &Path) -> Option<u8> {
    let s = fs::read_to_string(path).ok()?;
    let val = s.trim().parse::<u64>().ok()?;
    Some(val.min(255) as u8)
}

fn hfi_paths_for_cpu(cpu: usize) -> Option<HfiPaths> {
    let base = PathBuf::from(format!("/sys/devices/system/cpu/cpu{}/hfi", cpu));
    if !base.is_dir() {
        return None;
    }

    let candidates = [("perf", "eff"), ("performance", "energy_efficiency"), ("performance", "efficiency")];

    for (perf, eff) in candidates {
        let perf_path = base.join(perf);
        let eff_path = base.join(eff);
        if perf_path.exists() && eff_path.exists() {
            return Some(HfiPaths {
                perf: perf_path,
                eff: eff_path,
            });
        }
    }

    None
}

fn read_hfi_caps(paths: &HfiPaths) -> Option<(u8, u8)> {
    let perf = read_u8_from_file(&paths.perf)?;
    let eff = read_u8_from_file(&paths.eff)?;
    Some((perf, eff))
}

fn discover_hfi_paths(nr_cpus: usize) -> Vec<Option<HfiPaths>> {
    let mut paths = Vec::with_capacity(nr_cpus);
    for cpu in 0..nr_cpus {
        paths.push(hfi_paths_for_cpu(cpu));
    }
    paths
}

fn detect_core_tiers_by_hfi(nr_cpus: usize) -> Option<CoreTiers> {
    let paths = discover_hfi_paths(nr_cpus);
    let mut perfs: Vec<(usize, u8)> = Vec::new();

    for (cpu, p) in paths.iter().enumerate() {
        if let Some(paths) = p {
            if let Some((perf, _eff)) = read_hfi_caps(paths) {
                perfs.push((cpu, perf));
            }
        }
    }

    if perfs.len() < (nr_cpus / 2).max(1) {
        return None;
    }

    let mut perf_vals: Vec<u8> = perfs.iter().map(|(_, v)| *v).collect();
    perf_vals.sort_unstable();
    let p1 = perf_vals[perf_vals.len() / 3];
    let p2 = perf_vals[(perf_vals.len() * 2) / 3];

    if p1 == p2 {
        return None;
    }

    let mut lp_cpus = Vec::new();
    let mut e_cpus = Vec::new();
    let mut p_cpus = Vec::new();

    for cpu in 0..nr_cpus {
        if let Some(paths) = &paths[cpu] {
            if let Some((perf, _eff)) = read_hfi_caps(paths) {
                if perf <= p1 {
                    lp_cpus.push(cpu as u32);
                } else if perf >= p2 {
                    p_cpus.push(cpu as u32);
                } else {
                    e_cpus.push(cpu as u32);
                }
                continue;
            }
        }
        e_cpus.push(cpu as u32);
    }

    Some(CoreTiers {
        lp_cpus,
        e_cpus,
        p_cpus,
    })
}

/// Detect the three core tiers by max frequency or HFI.
fn detect_core_tiers(nr_cpus: usize) -> Result<CoreTiers> {
    let mut lp_cpus = Vec::new();
    let mut e_cpus = Vec::new();
    let mut p_cpus = Vec::new();

    if let Some(tiers) = detect_core_tiers_by_hfi(nr_cpus) {
        info!("Core tiers detected via HFI perf clustering");
        return Ok(tiers);
    }

    for cpu in 0..nr_cpus {
        let freq = read_max_freq_khz(cpu);

        match freq {
            Some(f) if f > P_FREQ_THRESH_KHZ => {
                debug!("cpu{}: {}kHz → P-core", cpu, f);
                p_cpus.push(cpu as u32);
            }
            Some(f) if f > E_FREQ_THRESH_KHZ => {
                debug!("cpu{}: {}kHz → E-core", cpu, f);
                e_cpus.push(cpu as u32);
            }
            Some(f) => {
                debug!("cpu{}: {}kHz → LP E-core", cpu, f);
                lp_cpus.push(cpu as u32);
            }
            None => {
                warn!("cpu{}: cannot read max_freq, assuming E-core", cpu);
                e_cpus.push(cpu as u32);
            }
        }
    }

    // Fallback: if no LP E-cores found, use CoreType from scx_utils
    if lp_cpus.is_empty() {
        warn!("No LP E-cores detected by frequency; falling back to CoreType heuristic");
        let topo = Topology::new()?;
        lp_cpus.clear();
        e_cpus.clear();
        p_cpus.clear();

        for (_core_id, core) in &topo.all_cores {
            for (&cpu_id, cpu) in &core.cpus {
                let id = cpu_id as u32;
                match &cpu.core_type {
                    CoreType::Little => lp_cpus.push(id),
                    CoreType::Big { turbo: false } => e_cpus.push(id),
                    CoreType::Big { turbo: true } => p_cpus.push(id),
                }
            }
        }
    }

    // If still no distinction, put everything on E
    if p_cpus.is_empty() && e_cpus.is_empty() {
        warn!("Cannot detect distinct core types; treating all CPUs as E-cores");
        for cpu in 0..nr_cpus {
            e_cpus.push(cpu as u32);
        }
    }

    info!(
        "Core tiers: LP E-cores={:?}, E-cores={:?}, P-cores={:?}",
        lp_cpus, e_cpus, p_cpus
    );

    Ok(CoreTiers {
        lp_cpus,
        e_cpus,
        p_cpus,
    })
}

/// Macro-like helper: sets CPU topology in rodata.
/// Called where `rodata` is already dereferenced (inferred type from skeleton).
macro_rules! upload_topology {
    ($rodata:expr, $tiers:expr, $nr_cpus:expr) => {{
        let tiers = $tiers;
        let nr_cpus = $nr_cpus;
        let rodata = $rodata;

        for &cpu in &tiers.lp_cpus {
            if (cpu as usize) < nr_cpus && (cpu as usize) < rodata.cpu_core_type.len() {
                rodata.cpu_core_type[cpu as usize] = 0; // CORE_LP
            }
        }
        for &cpu in &tiers.e_cpus {
            if (cpu as usize) < nr_cpus && (cpu as usize) < rodata.cpu_core_type.len() {
                rodata.cpu_core_type[cpu as usize] = 1; // CORE_E
            }
        }
        for &cpu in &tiers.p_cpus {
            if (cpu as usize) < nr_cpus && (cpu as usize) < rodata.cpu_core_type.len() {
                rodata.cpu_core_type[cpu as usize] = 2; // CORE_P
            }
        }

        rodata.nr_lp_cpus = tiers.lp_cpus.len() as u32;
        rodata.nr_e_cpus = tiers.e_cpus.len() as u32;
        rodata.nr_p_cpus = tiers.p_cpus.len() as u32;

        for (i, &cpu) in tiers.lp_cpus.iter().enumerate() {
            if i < rodata.lp_cpus.len() {
                rodata.lp_cpus[i] = cpu;
            }
        }
        for (i, &cpu) in tiers.e_cpus.iter().enumerate() {
            if i < rodata.e_cpus.len() {
                rodata.e_cpus[i] = cpu;
            }
        }
        for (i, &cpu) in tiers.p_cpus.iter().enumerate() {
            if i < rodata.p_cpus.len() {
                rodata.p_cpus[i] = cpu;
            }
        }
    }};
}

/// Path to the persistent procdb file.
fn procdb_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("scx-meteor")
        .join("profiles.db")
}

/// Load procdb profiles from disk into BPF proc_profiles map.
fn load_procdb(skel: &BpfSkel<'_>) -> Result<usize> {
    let path = procdb_path();
    if !path.exists() {
        return Ok(0);
    }

    let data = fs::read_to_string(&path)?;
    let profiles: HashMap<String, ProcProfile> = serde_json::from_str(&data)?;
    let mut loaded = 0usize;

    for (comm, profile) in &profiles {
        let mut key = [0u8; 16];
        let bytes = comm.as_bytes();
        let len = bytes.len().min(15);
        key[..len].copy_from_slice(&bytes[..len]);

        let mut bpf_profile: proc_profile = unsafe { std::mem::zeroed() };
        bpf_profile.tier = profile.tier;
        bpf_profile.confidence = profile.confidence;
        bpf_profile.vol_ctx_per_sec = profile.vol_ctx_per_sec;
        bpf_profile.wakeups_per_sec = profile.wakeups_per_sec;
        bpf_profile.observations = profile.observations;
        bpf_profile.avg_burst_ns = profile.avg_burst_ns;
        bpf_profile.avg_sleep_ns = profile.avg_sleep_ns;
        bpf_profile.total_runtime_ns = profile.total_runtime_ns;
        bpf_profile.last_seen_ns = 0;

        let val_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &bpf_profile as *const _ as *const u8,
                std::mem::size_of::<proc_profile>(),
            )
        };

        if let Err(e) = skel
            .maps
            .proc_profiles
            .update(&key, val_bytes, libbpf_rs::MapFlags::ANY)
        {
            warn!("procdb: failed to load '{}': {}", comm, e);
        } else {
            loaded += 1;
        }
    }

    info!("procdb: loaded {} profiles from {:?}", loaded, path);
    Ok(loaded)
}

/// Drain the BPF observation map and persist to disk.
fn save_procdb(skel: &BpfSkel<'_>) -> Result<()> {
    let path = procdb_path();

    let mut profiles: HashMap<String, ProcProfile> = if path.exists() {
        let data = fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Drain the BPF observation map (comm → proc_profile)
    let obs_keys: Vec<Vec<u8>> = skel.maps.procdb_observations.keys().collect();
    let mut merged = 0usize;

    for key in &obs_keys {
        if let Ok(Some(val_bytes)) =
            skel.maps
                .procdb_observations
                .lookup(key, libbpf_rs::MapFlags::ANY)
        {
            let val_bytes: Vec<u8> = val_bytes;
            if val_bytes.len() < std::mem::size_of::<proc_profile>() {
                continue;
            }
            let bpf_profile: proc_profile =
                unsafe { std::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };

            let comm = String::from_utf8_lossy(key)
                .trim_end_matches('\0')
                .to_string();
            if comm.is_empty() {
                continue;
            }

            let existing = profiles.entry(comm).or_insert(ProcProfile {
                tier: bpf_profile.tier,
                confidence: 0,
                vol_ctx_per_sec: bpf_profile.vol_ctx_per_sec,
                wakeups_per_sec: bpf_profile.wakeups_per_sec,
                observations: 0,
                avg_burst_ns: bpf_profile.avg_burst_ns,
                avg_sleep_ns: bpf_profile.avg_sleep_ns,
                total_runtime_ns: bpf_profile.total_runtime_ns,
            });

            // EWMA merge: 75% old + 25% new
            existing.avg_burst_ns =
                (existing.avg_burst_ns - (existing.avg_burst_ns >> 2)) + (bpf_profile.avg_burst_ns >> 2);
            existing.vol_ctx_per_sec =
                (existing.vol_ctx_per_sec - (existing.vol_ctx_per_sec >> 2)) + (bpf_profile.vol_ctx_per_sec >> 2);
            existing.wakeups_per_sec =
                (existing.wakeups_per_sec - (existing.wakeups_per_sec >> 2)) + (bpf_profile.wakeups_per_sec >> 2);
            existing.avg_sleep_ns =
                (existing.avg_sleep_ns - (existing.avg_sleep_ns >> 2)) + (bpf_profile.avg_sleep_ns >> 2);
            existing.observations = existing.observations.saturating_add(bpf_profile.observations);
            existing.confidence = existing.confidence.saturating_add(5).min(100);
            existing.tier = bpf_profile.tier;
            existing.total_runtime_ns = existing
                .total_runtime_ns
                .saturating_add(bpf_profile.total_runtime_ns);

            merged += 1;
        }
    }

    if merged == 0 {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("tmp");
    let json = serde_json::to_string_pretty(&profiles)?;
    fs::write(&tmp_path, &json)?;
    fs::rename(&tmp_path, &path)?;

    info!("procdb: persisted {} profiles → {:?}", profiles.len(), path);
    Ok(())
}

fn comm_key(comm: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = comm.as_bytes();
    let len = bytes.len().min(15);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

fn update_comm_rule(
    skel: &BpfSkel<'_>,
    comm: &str,
    tier: u8,
    mode: u8,
) -> Result<()> {
    let key = comm_key(comm);
    let mut rule: tier_rule = unsafe { std::mem::zeroed() };
    rule.tier = tier;
    rule.mode = mode;
    let val_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            &rule as *const _ as *const u8,
            std::mem::size_of::<tier_rule>(),
        )
    };
    skel.maps
        .comm_rules
        .update(&key, val_bytes, libbpf_rs::MapFlags::ANY)?;
    Ok(())
}

fn cgroup_id_from_path(path: &Path) -> Result<u64> {
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from("/sys/fs/cgroup").join(path)
    };
    let meta = fs::metadata(&full_path)?;
    Ok(meta.ino())
}

fn update_cgroup_rule(
    skel: &BpfSkel<'_>,
    cgroup_id: u64,
    tier: u8,
    mode: u8,
) -> Result<()> {
    let key = cgroup_id.to_ne_bytes();
    let mut rule: tier_rule = unsafe { std::mem::zeroed() };
    rule.tier = tier;
    rule.mode = mode;
    let val_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            &rule as *const _ as *const u8,
            std::mem::size_of::<tier_rule>(),
        )
    };
    skel.maps
        .cgroup_rules
        .update(&key, val_bytes, libbpf_rs::MapFlags::ANY)?;
    Ok(())
}

fn update_hfi_caps_map(skel: &BpfSkel<'_>, paths: &[Option<HfiPaths>]) -> Result<()> {
    for (cpu, p) in paths.iter().enumerate() {
        let mut caps: hfi_caps = unsafe { std::mem::zeroed() };
        if let Some(paths) = p {
            if let Some((perf, eff)) = read_hfi_caps(paths) {
                caps.perf = perf;
                caps.eff = eff;
                caps.valid = 1;
            }
        }
        let key = (cpu as u32).to_ne_bytes();
        let val_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &caps as *const _ as *const u8,
                std::mem::size_of::<hfi_caps>(),
            )
        };
        skel.maps
            .hfi_caps_map
            .update(&key, val_bytes, libbpf_rs::MapFlags::ANY)?;
    }
    Ok(())
}

/// scx_meteor_v2 command-line options.
#[derive(Debug, Parser)]
#[command(
    name = SCHEDULER_NAME,
    about = "Intel Meteor Lake LP-first energy-aware sched_ext scheduler",
    long_about = "
scx_meteor_v2: 3-tier scheduler for Intel Meteor Lake (Core Ultra 9 185H)

Core types:
  LP E-cores  (SoC tile)   — idle/background tasks, Compute tile stays OFF
  E-cores  (Compute tile)  — general-purpose workloads
  P-cores  (Compute tile)  — interactive / CPU-heavy tasks (race-to-idle)

Strategy: tasks start on LP E-cores (Apple-style: earn your tier).
Burst > lp_burst_ms  → escalate LP→E (Compute tile wakes).
Burst > e_burst_ms   → escalate E→P  (full performance).
Quiet for drain_ms   → drain-back toward LP.
procdb remembers per-process behavior across reboots.
"
)]
struct Opts {
    /// Time slice duration in microseconds.
    #[clap(short = 's', long, default_value = "2000")]
    slice_us: u64,

    /// LP → E burst escalation threshold in milliseconds.
    #[clap(short = 'b', long, default_value = "5")]
    lp_burst_ms: u64,

    /// E → P burst escalation threshold in milliseconds.
    #[clap(short = 'B', long, default_value = "30")]
    e_burst_ms: u64,

    /// Drain-back delay after task quiets down (milliseconds).
    #[clap(short = 'd', long, default_value = "500")]
    drain_delay_ms: u64,

    /// Wakeup frequency threshold (per 100ms) to promote LP→E as interactive.
    #[clap(short = 'i', long, default_value = "10")]
    interactive_wakeup_freq: u64,

    /// System load (%) below which we force all tasks to LP E-cores.
    #[clap(long, default_value = "10")]
    lp_only_load_pct: u32,

    /// LP-only hysteresis (%) to exit LP-only mode.
    #[clap(long, default_value = "5")]
    lp_only_hyst_pct: u32,

    /// Strict LP: do not allow LP-tier tasks on E/P cores.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    strict_lp: bool,

    /// Allow LP cores to help E-tier tasks when LP DSQ is empty.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    lp_can_help_e: bool,

    /// Fast-burst window for first-run escalation (ms).
    #[clap(long, default_value = "10")]
    fast_burst_ms: u64,

    /// Require N consecutive bursts before escalating.
    #[clap(long, default_value = "2")]
    burst_up_streak: u32,

    /// Short-burst threshold for interactive detection (us).
    #[clap(long, default_value = "500")]
    interactive_short_burst_us: u64,

    /// Voluntary context switch rate threshold (per sec).
    #[clap(long, default_value = "50")]
    interactive_csw_rate: u32,

    /// CPU-bound burst threshold for degradable priorities (ms).
    #[clap(long, default_value = "20")]
    cpu_bound_burst_ms: u64,

    /// CPU-bound total runtime before demotion (ms).
    #[clap(long, default_value = "200")]
    cpu_bound_total_ms: u64,

    /// Bursty window duration (ms).
    #[clap(long, default_value = "500")]
    bursty_window_ms: u64,

    /// Bursty threshold (events per window).
    #[clap(long, default_value = "3")]
    bursty_threshold: u32,

    /// Bursty hold duration (ms).
    #[clap(long, default_value = "1000")]
    bursty_hold_ms: u64,

    /// Minimum procdb confidence (observations) before trusting a profile.
    #[clap(short = 'c', long, default_value = "3")]
    procdb_confidence_min: u32,

    /// How often to persist procdb to disk in seconds (0 = exit only).
    #[clap(short = 'p', long, default_value = "30")]
    procdb_save_interval_s: u64,

    /// HFI polling interval in milliseconds (0 = disable).
    #[clap(long, default_value = "1000")]
    hfi_poll_ms: u64,

    /// Cgroup paths to force into LP tier (background.slice).
    #[clap(long, value_delimiter = ',')]
    background_cgroup: Vec<PathBuf>,

    /// Cgroup IDs to force into LP tier (background.slice).
    #[clap(long, value_delimiter = ',')]
    background_cgroup_id: Vec<u64>,

    /// Comms that should never run on LP (min tier = E).
    #[clap(long, value_delimiter = ',')]
    no_lp_comm: Vec<String>,

    /// Comms that should always be interactive (force tier = P).
    #[clap(long, value_delimiter = ',')]
    interactive_comm: Vec<String>,

    /// Enable stats monitoring with the given interval (seconds).
    #[clap(long)]
    stats: Option<f64>,

    /// Monitor-only mode: display stats from a running scheduler.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable BPF debug output via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'D', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show stats field descriptions.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
    tiers: CoreTiers,
    stats_server: StatsServer<(), Metrics>,
    procdb_save_interval: Option<Duration>,
    last_procdb_save: std::time::Instant,
    hfi_paths: Vec<Option<HfiPaths>>,
    hfi_update_interval: Duration,
    last_hfi_update: Instant,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let nr_cpus = *NR_CPU_IDS;
        let tiers = detect_core_tiers(nr_cpus)?;

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        info!("scheduler args: {}", std::env::args().collect::<Vec<_>>().join(" "));

        // Open BPF skeleton
        let mut skel_builder = BpfSkelBuilder::default();
        // Always enable libbpf debug output so verifier errors are visible
        skel_builder.obj_builder.debug(true);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, meteor_ops, open_opts)?;

        // Set tunables in rodata
        {
            let rodata = skel.maps.rodata_data.as_mut().unwrap();
            rodata.slice_ns = opts.slice_us * 1000;
            rodata.lp_burst_thresh_ns = opts.lp_burst_ms * 1_000_000;
            rodata.e_burst_thresh_ns = opts.e_burst_ms * 1_000_000;
            rodata.drain_delay_ns = opts.drain_delay_ms * 1_000_000;
            rodata.interactive_wakeup_freq = opts.interactive_wakeup_freq;
            rodata.procdb_confidence_min = opts.procdb_confidence_min;
            rodata.lp_only_load_pct = opts.lp_only_load_pct;
            rodata.lp_only_hyst_pct = opts.lp_only_hyst_pct;
            rodata.strict_lp = opts.strict_lp;
            rodata.lp_can_help_e = opts.lp_can_help_e;
            rodata.fast_burst_window_ns = opts.fast_burst_ms * 1_000_000;
            rodata.burst_up_streak = opts.burst_up_streak;
            rodata.interactive_short_burst_ns = opts.interactive_short_burst_us * 1_000;
            rodata.interactive_csw_rate = opts.interactive_csw_rate;
            rodata.cpu_bound_burst_ns = opts.cpu_bound_burst_ms * 1_000_000;
            rodata.cpu_bound_total_ns = opts.cpu_bound_total_ms * 1_000_000;
            rodata.bursty_window_ns = opts.bursty_window_ms * 1_000_000;
            rodata.bursty_threshold = opts.bursty_threshold;
            rodata.bursty_hold_ns = opts.bursty_hold_ms * 1_000_000;
            rodata.debug = opts.debug;
            upload_topology!(rodata, &tiers, nr_cpus);
        }

        // Load the BPF skeleton
        let mut skel = scx_ops_load!(skel, meteor_ops, uei)?;

        // Restore procdb from disk
        if let Err(e) = load_procdb(&skel) {
            warn!("procdb: load failed (non-fatal): {}", e);
        }

        // Apply comm-based overrides
        for comm in &opts.no_lp_comm {
            if let Err(e) = update_comm_rule(&skel, comm, TIER_E_U8, TIER_RULE_MIN_U8) {
                warn!("comm rule (no-lp) '{}' failed: {}", comm, e);
            }
        }
        for comm in &opts.interactive_comm {
            if let Err(e) = update_comm_rule(&skel, comm, TIER_P_U8, TIER_RULE_FORCE_U8) {
                warn!("comm rule (interactive) '{}' failed: {}", comm, e);
            }
        }

        // Apply cgroup-based overrides (background.slice)
        let mut bg_paths = opts.background_cgroup.clone();
        let default_bg = PathBuf::from("/sys/fs/cgroup/background.slice");
        if bg_paths.is_empty() && default_bg.exists() {
            bg_paths.push(default_bg);
        }

        for path in &bg_paths {
            match cgroup_id_from_path(path) {
                Ok(id) => {
                    if let Err(e) = update_cgroup_rule(&skel, id, TIER_LP_U8, TIER_RULE_FORCE_U8) {
                        warn!("cgroup rule {:?} failed: {}", path, e);
                    }
                }
                Err(e) => warn!("cgroup id lookup failed for {:?}: {}", path, e),
            }
        }
        for id in &opts.background_cgroup_id {
            if let Err(e) = update_cgroup_rule(&skel, *id, TIER_LP_U8, TIER_RULE_FORCE_U8) {
                warn!("cgroup rule id {} failed: {}", id, e);
            }
        }

        // Initialize HFI caps map (if available)
        let hfi_paths = if opts.hfi_poll_ms == 0 {
            Vec::new()
        } else {
            let paths = discover_hfi_paths(nr_cpus);
            if paths.iter().any(|p| p.is_some()) {
                if let Err(e) = update_hfi_caps_map(&skel, &paths) {
                    warn!("hfi: initial update failed: {}", e);
                } else {
                    info!("hfi: initial caps loaded");
                }
                paths
            } else {
                Vec::new()
            }
        };

        // Set up stats server
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Attach the scheduler
        let struct_ops = Some(scx_ops_attach!(skel, meteor_ops)?);

        info!("{} running", SCHEDULER_NAME);

        Ok(Scheduler {
            skel,
            struct_ops,
            opts,
            tiers,
            stats_server,
            procdb_save_interval: if opts.procdb_save_interval_s == 0 {
                None
            } else {
                Some(Duration::from_secs(opts.procdb_save_interval_s.max(5)))
            },
            last_procdb_save: std::time::Instant::now(),
            hfi_paths,
            hfi_update_interval: Duration::from_millis(opts.hfi_poll_ms.max(100)),
            last_hfi_update: Instant::now(),
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss.nr_running,
            nr_lp_direct: bss.nr_lp_direct,
            nr_lp_shared: bss.nr_lp_shared,
            nr_e_direct: bss.nr_e_direct,
            nr_e_shared: bss.nr_e_shared,
            nr_p_direct: bss.nr_p_direct,
            nr_p_shared: bss.nr_p_shared,
            nr_escalations: bss.nr_escalations,
            nr_drainbacks: bss.nr_drainbacks,
            nr_procdb_hits: bss.nr_procdb_hits,
            nr_lp_only_forced: bss.nr_lp_only_forced,
            nr_interactive_promos: bss.nr_interactive_promos,
            nr_cpu_bound_demotes: bss.nr_cpu_bound_demotes,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Periodic procdb save
            if let Some(intv) = self.procdb_save_interval {
                if self.last_procdb_save.elapsed() >= intv {
                    if let Err(e) = save_procdb(&self.skel) {
                        warn!("procdb: save failed: {}", e);
                    }
                    self.last_procdb_save = std::time::Instant::now();
                }
            }

            // Periodic HFI caps update
            if !self.hfi_paths.is_empty()
                && self.last_hfi_update.elapsed() >= self.hfi_update_interval
            {
                if let Err(e) = update_hfi_caps_map(&self.skel, &self.hfi_paths) {
                    warn!("hfi: update failed: {}", e);
                }
                self.last_hfi_update = Instant::now();
            }

            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Final procdb save
        if let Err(e) = save_procdb(&self.skel) {
            warn!("procdb: final save failed: {}", e);
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = if opts.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                warn!("stats monitor: {}", e);
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
