/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_meteor_v2: sched_ext scheduler for Intel Meteor Lake / Core Ultra 9 185H
 *
 * 3-tier core architecture:
 *   P-cores  (Compute tile, Redwood Cove)  — interactive / CPU-bound
 *   E-cores  (Compute tile, Crestmont)     — general-purpose
 *   LP E-cores (SoC tile, Low Power Island) — idle/background → Compute tile OFF
 *
 * Strategy: LP-first, burst-escalate to E/P, drain-back to LP.
 * Inspired by: scx_bpfland, PANDEMONIUM, Apple QoS, intel-lpmd.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#ifndef __VMLINUX_H__
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed char    s8;
typedef signed short   s16;
typedef signed int     s32;
typedef signed long    s64;
typedef int pid_t;
#endif /* __VMLINUX_H__ */

#define MAX(x, y)         ((x) > (y) ? (x) : (y))
#define MIN(x, y)         ((x) < (y) ? (x) : (y))
#define CLAMP(v, lo, hi)  MIN(MAX(v, lo), hi)
#define ARRAY_SIZE(x)     (sizeof(x) / sizeof((x)[0]))

/* ------------------------------------------------------------------ */
/* Core type constants                                                */
/* ------------------------------------------------------------------ */
enum core_type {
	CORE_LP = 0,   /* LP E-core (SoC tile, Low Power Island) */
	CORE_E  = 1,   /* E-core   (Compute tile, Crestmont)     */
	CORE_P  = 2,   /* P-core   (Compute tile, Redwood Cove)  */
};

/* ------------------------------------------------------------------ */
/* Task scheduling tiers                                              */
/* ------------------------------------------------------------------ */
enum task_tier {
	TIER_LP = 0,   /* run on LP E-cores  (Compute tile stays OFF)  */
	TIER_E  = 1,   /* run on E-cores     (Compute tile wakes up)   */
	TIER_P  = 2,   /* run on P-cores     (race-to-idle for heavy)  */
};

/* ------------------------------------------------------------------ */
/* Tier rule modes (for comm/cgroup overrides)                        */
/* ------------------------------------------------------------------ */
enum tier_rule_mode {
	TIER_RULE_FORCE = 0, /* force exact tier */
	TIER_RULE_MIN   = 1, /* minimum tier (can be higher) */
};

struct tier_rule {
	u8 tier;  /* enum task_tier */
	u8 mode;  /* enum tier_rule_mode */
};

/* ------------------------------------------------------------------ */
/* HFI capabilities (per-CPU, userspace-updated)                       */
/* ------------------------------------------------------------------ */
struct hfi_caps {
	u8 perf;   /* 0-255 */
	u8 eff;    /* 0-255 */
	u8 valid;  /* 0/1 */
	u8 _pad;   /* align */
};

/* ------------------------------------------------------------------ */
/* Persistent per-process profile (BPF hash map: comm → proc_profile) */
/* Userspace serialises this to ~/.config/scx-meteor/profiles.db      */
/* ------------------------------------------------------------------ */
struct proc_profile {
	u8  tier;             /* last observed TIER_LP/E/P              */
	u8  confidence;       /* 0-100, grows with observations         */
	u16 _pad;
	u32 vol_ctx_per_sec;  /* EWMA voluntary ctx switches/sec        */
	u32 wakeups_per_sec;  /* EWMA wakeups/sec                       */
	u32 observations;     /* total observation count                */
	u64 avg_burst_ns;     /* EWMA CPU burst duration (ns)           */
	u64 avg_sleep_ns;     /* EWMA sleep duration (ns)               */
	u64 total_runtime_ns; /* cumulative runtime (ns)                */
	u64 last_seen_ns;     /* bpf_ktime_get_ns() of last update      */
};

#define PROC_COMM_LEN  16

/* ------------------------------------------------------------------ */
/* Stats published to userspace via BPF maps                          */
/* ------------------------------------------------------------------ */
struct meteor_stats {
	u64 nr_running;
	u64 nr_lp_direct;    /* direct dispatches to LP E-cores  */
	u64 nr_e_direct;     /* direct dispatches to E-cores     */
	u64 nr_p_direct;     /* direct dispatches to P-cores     */
	u64 nr_lp_shared;    /* enqueued to shared LP DSQ        */
	u64 nr_e_shared;     /* enqueued to shared E DSQ         */
	u64 nr_p_shared;     /* enqueued to shared P DSQ         */
	u64 nr_escalations;  /* TIER_LP → TIER_E → TIER_P        */
	u64 nr_drainbacks;   /* TIER_P → TIER_E → TIER_LP        */
	u64 nr_procdb_hits;  /* tasks classified via procdb      */
	u64 nr_lp_only_forced;
	u64 nr_interactive_promos;
	u64 nr_cpu_bound_demotes;
};

/* ------------------------------------------------------------------ */
/* Syscall prog argument: set core type for a CPU                     */
/* ------------------------------------------------------------------ */
struct set_core_type_arg {
	s32 cpu_id;
	u8  core_type;   /* enum core_type */
};

#endif /* __INTF_H */
