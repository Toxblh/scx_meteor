// SPDX-License-Identifier: GPL-2.0
//
// scx_meteor_v2 — stats definitions

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Currently running tasks")]
    pub nr_running: u64,

    #[stat(desc = "Direct dispatches to LP E-cores (SoC tile)")]
    pub nr_lp_direct: u64,

    #[stat(desc = "Shared-DSQ enqueues to LP E-cores")]
    pub nr_lp_shared: u64,

    #[stat(desc = "Direct dispatches to E-cores (Compute tile)")]
    pub nr_e_direct: u64,

    #[stat(desc = "Shared-DSQ enqueues to E-cores")]
    pub nr_e_shared: u64,

    #[stat(desc = "Direct dispatches to P-cores (Compute tile)")]
    pub nr_p_direct: u64,

    #[stat(desc = "Shared-DSQ enqueues to P-cores")]
    pub nr_p_shared: u64,

    #[stat(desc = "Tier escalations LP→E or E→P (burst detected)")]
    pub nr_escalations: u64,

    #[stat(desc = "Tier drain-backs P→E or E→LP (task quieted)")]
    pub nr_drainbacks: u64,

    #[stat(desc = "Tasks classified using persistent procdb")]
    pub nr_procdb_hits: u64,

    #[stat(desc = "Tasks forced to LP due to LP-only mode")]
    pub nr_lp_only_forced: u64,

    #[stat(desc = "Interactive promotions from LP")]
    pub nr_interactive_promos: u64,

    #[stat(desc = "CPU-bound demotions (degradable priorities)")]
    pub nr_cpu_bound_demotes: u64,
}

impl Metrics {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[scx_meteor_v2] running={:<3} LP={}/{} E={}/{} P={}/{} | esc={} drain={} procdb={} lp_only={} int_prom={} cpu_dem={}",
            self.nr_running,
            self.nr_lp_direct,
            self.nr_lp_shared,
            self.nr_e_direct,
            self.nr_e_shared,
            self.nr_p_direct,
            self.nr_p_shared,
            self.nr_escalations,
            self.nr_drainbacks,
            self.nr_procdb_hits,
            self.nr_lp_only_forced,
            self.nr_interactive_promos,
            self.nr_cpu_bound_demotes,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_lp_direct: self.nr_lp_direct.saturating_sub(rhs.nr_lp_direct),
            nr_lp_shared: self.nr_lp_shared.saturating_sub(rhs.nr_lp_shared),
            nr_e_direct: self.nr_e_direct.saturating_sub(rhs.nr_e_direct),
            nr_e_shared: self.nr_e_shared.saturating_sub(rhs.nr_e_shared),
            nr_p_direct: self.nr_p_direct.saturating_sub(rhs.nr_p_direct),
            nr_p_shared: self.nr_p_shared.saturating_sub(rhs.nr_p_shared),
            nr_escalations: self.nr_escalations.saturating_sub(rhs.nr_escalations),
            nr_drainbacks: self.nr_drainbacks.saturating_sub(rhs.nr_drainbacks),
            nr_procdb_hits: self.nr_procdb_hits.saturating_sub(rhs.nr_procdb_hits),
            nr_lp_only_forced: self
                .nr_lp_only_forced
                .saturating_sub(rhs.nr_lp_only_forced),
            nr_interactive_promos: self
                .nr_interactive_promos
                .saturating_sub(rhs.nr_interactive_promos),
            nr_cpu_bound_demotes: self
                .nr_cpu_bound_demotes
                .saturating_sub(rhs.nr_cpu_bound_demotes),
            ..self.clone()
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
