/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_meteor_v2 — Intel Meteor Lake / Core Ultra 9 185H scheduler
 *
 * Three-tier core topology:
 *   LP E-cores  (SoC tile)     — Low Power Island, no L3 cache
 *   E-cores     (Compute tile) — Crestmont, shared L3
 *   P-cores     (Compute tile) — Redwood Cove, shared L3
 *
 * Philosophy (LP-first, burst-up, drain-back):
 *   1. New tasks → LP E-cores by default (Compute tile OFF → saves watts)
 *   2. If task's avg_burst > threshold → escalate to E or P (race-to-idle)
 *   3. After task quiets down for drain_delay → migrate back to LP
 *
 * Per-process profile database (procdb):
 *   comm[16] → proc_profile (tier, confidence, avg_burst, wakeup_freq)
 *   Userspace persists this across reboots for warm-start classification.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* Kernel constants not always available in BPF context               */
/* ------------------------------------------------------------------ */
#ifndef SCHED_NORMAL
#define SCHED_NORMAL   0
#endif
#ifndef SCHED_FIFO
#define SCHED_FIFO     1
#endif
#ifndef SCHED_RR
#define SCHED_RR       2
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH    3
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE     5
#endif

/*
 * TASK_NICE: convert static_prio to nice value.
 * static_prio = nice + 120  (MAX_RT_PRIO = 100, so NICE_TO_PRIO = 120)
 */
#define TASK_NICE(p)  ((int)(p)->static_prio - 120)

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */
#define MAX_CPUS               32

/* DSQ identifiers */
#define DSQ_LP                 0ULL   /* shared LP E-core DSQ  */
#define DSQ_E                  1ULL   /* shared E-core DSQ     */
#define DSQ_P                  2ULL   /* shared P-core DSQ     */
#define DSQ_CPU_BASE           3ULL   /* per-CPU DSQ: cpu + DSQ_CPU_BASE */

/* EWMA weight: 75% old + 25% new */
#define EWMA_ALPHA_SHIFT       2      /* >> 2 = /4 */

/* ------------------------------------------------------------------ */
/* Tunables (set by userspace via BPF skeleton rodata)                */
/* ------------------------------------------------------------------ */
const volatile bool debug                 = false;

/* Time slice for all tasks (ns) */
const volatile u64 slice_ns              = 2000000ULL;  /* 2 ms */

/* Burst threshold: LP E-core → E-core escalation (ns) */
const volatile u64 lp_burst_thresh_ns   = 5000000ULL;  /* 5 ms */

/* Burst threshold: E-core → P-core escalation (ns) */
const volatile u64 e_burst_thresh_ns    = 30000000ULL; /* 30 ms */

/* Quiet time before drain-back (ns) */
const volatile u64 drain_delay_ns       = 500000000ULL;/* 500 ms */

/* Minimum observations before trusting procdb */
const volatile u32 procdb_confidence_min = 3;

/* Minimum wakeup freq (per 100ms) to consider task interactive */
const volatile u64 interactive_wakeup_freq = 10;

/* System-wide load below which we force all tasks to LP E-cores (%) */
const volatile u32 lp_only_load_pct     = 10;

/* LP-only hysteresis (% load to exit LP-only mode) */
const volatile u32 lp_only_hyst_pct     = 5;

/* Strict LP: do not allow LP-tier tasks to run on E/P cores */
const volatile bool strict_lp           = true;

/* Allow LP cores to help E-tier tasks when LP DSQ empty */
const volatile bool lp_can_help_e       = false;

/* Fast-burst window for first-run escalation (ns) */
const volatile u64 fast_burst_window_ns = 10000000ULL; /* 10 ms */

/* Require N consecutive bursts before escalating */
const volatile u32 burst_up_streak      = 2;

/* Short-burst threshold for interactive detection (ns) */
const volatile u64 interactive_short_burst_ns = 500000ULL; /* 0.5 ms */

/* Voluntary ctx switch rate threshold for interactivity (per sec) */
const volatile u32 interactive_csw_rate = 50;

/* CPU-bound demotion thresholds */
const volatile u64 cpu_bound_burst_ns   = 20000000ULL;  /* 20 ms */
const volatile u64 cpu_bound_total_ns   = 200000000ULL; /* 200 ms */

/* Bursty task pattern detection */
const volatile u64 bursty_window_ns     = 500000000ULL; /* 500 ms */
const volatile u32 bursty_threshold     = 3;
const volatile u64 bursty_hold_ns       = 1000000000ULL;/* 1 s */

/* ------------------------------------------------------------------ */
/* CPU topology (set by userspace on init)                            */
/* ------------------------------------------------------------------ */
/* Core type for each CPU: CORE_LP / CORE_E / CORE_P */
const volatile u8 cpu_core_type[MAX_CPUS];

/* Sorted CPU lists per tier (set by userspace) */
const volatile u32 nr_lp_cpus;
const volatile u32 nr_e_cpus;
const volatile u32 nr_p_cpus;
const volatile u32 lp_cpus[MAX_CPUS];
const volatile u32 e_cpus[MAX_CPUS];
const volatile u32 p_cpus[MAX_CPUS];

/* ------------------------------------------------------------------ */
/* Global scheduling state                                            */
/* ------------------------------------------------------------------ */
static u64 nr_cpu_ids;

/* Virtual time for inter-tier fairness */
static u64 vtime_now;

/* Running task count */
volatile u64 nr_running;

/* Dispatch stats */
volatile u64 nr_lp_direct, nr_e_direct, nr_p_direct;
volatile u64 nr_lp_shared, nr_e_shared, nr_p_shared;
volatile u64 nr_escalations, nr_drainbacks, nr_procdb_hits;
volatile u64 nr_interactive_promos, nr_cpu_bound_demotes;
volatile u64 nr_lp_only_forced;

/* ------------------------------------------------------------------ */
/* Debug helper                                                        */
/* ------------------------------------------------------------------ */
#define dbg(fmt, ...) do {                    \
	if (debug)                            \
		bpf_printk(fmt, ##__VA_ARGS__);\
} while (0)

/* ------------------------------------------------------------------ */
/* Exit info                                                           */
/* ------------------------------------------------------------------ */
UEI_DEFINE(uei);

/* ------------------------------------------------------------------ */
/* Per-task context (BPF_MAP_TYPE_TASK_STORAGE)                       */
/* ------------------------------------------------------------------ */
struct task_ctx {
	u8  tier;           /* current TIER_LP / TIER_E / TIER_P     */
	u8  min_tier;       /* minimum tier allowed (comm/cgroup)    */
	u8  force_tier;     /* forced tier from comm/cgroup rule     */
	u8  force_valid;    /* force_tier is valid                   */
	u8  sync_wake;      /* last wake was synchronous (waker-wakee) */
	u64 last_run_at;    /* bpf_ktime_get_ns() when run started   */
	u64 first_run_at;   /* first time task ran (ns)              */
	u64 avg_burst_ns;   /* EWMA of CPU burst duration            */
	u64 avg_sleep_ns;   /* EWMA of sleep duration                */
	u64 total_runtime_ns; /* cumulative runtime                   */
	u64 last_quiet_at;  /* when burst last dropped below thresh  */
	u64 last_woke_at;   /* timestamp of last wakeup              */
	u64 wakeup_freq;    /* EWMA wakeups per 100ms window         */
	u64 awake_vtime;    /* vruntime accumulated since last sleep  */
	u64 last_sleep_at;  /* timestamp when task went to sleep     */
	u64 last_nvcsw_at;  /* timestamp of last nvcsw snapshot      */
	u64 last_nvcsw;     /* last nvcsw value                      */
	u64 cpu_bound_ns;   /* accumulated CPU-bound runtime         */
	u64 bursty_until;   /* hold tier >= E until this time        */
	u32 observations;   /* number of completed scheduling cycles */
	u32 vol_ctx_per_sec;/* EWMA voluntary ctx switches per sec   */
	u32 burst_streak_lp;/* consecutive bursts over LP threshold  */
	u32 burst_streak_e; /* consecutive bursts over E threshold   */
	u32 bursty_count;   /* bursts within current window          */
	u64 bursty_window_start; /* window start timestamp           */
	u8  procdb_loaded;  /* initial tier came from procdb         */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* ------------------------------------------------------------------ */
/* Per-process persistent profile (procdb)                            */
/* key: comm[PROC_COMM_LEN], value: proc_profile                     */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[PROC_COMM_LEN]);
	__type(value, struct proc_profile);
} proc_profiles SEC(".maps");

/* ------------------------------------------------------------------ */
/* Observation map: BPF → Rust (profiles to persist)                 */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[PROC_COMM_LEN]);
	__type(value, struct proc_profile);
} procdb_observations SEC(".maps");

/* ------------------------------------------------------------------ */
/* HFI capabilities per CPU (perf/eff), updated from userspace         */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, struct hfi_caps);
} hfi_caps_map SEC(".maps");

/* ------------------------------------------------------------------ */
/* Per-comm tier overrides (force or min tier)                        */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[PROC_COMM_LEN]);
	__type(value, struct tier_rule);
} comm_rules SEC(".maps");

/* ------------------------------------------------------------------ */
/* Per-cgroup tier overrides (force or min tier)                      */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, struct tier_rule);
} cgroup_rules SEC(".maps");

/* ------------------------------------------------------------------ */
/* LP-only state (map to avoid BTF .bss size issues)                  */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} lp_only_state_map SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helper: EWMA (75% old + 25% new)                                   */
/* ------------------------------------------------------------------ */
static inline u64 ewma(u64 old, u64 new_val)
{
	return (old - (old >> EWMA_ALPHA_SHIFT)) + (new_val >> EWMA_ALPHA_SHIFT);
}

/* ------------------------------------------------------------------ */
/* Helper: wakeup frequency (wakeups per 100ms window)               */
/* ------------------------------------------------------------------ */
static inline u64 update_wakeup_freq(u64 freq, u64 interval_ns)
{
	u64 new_freq;

	if (interval_ns == 0)
		interval_ns = 1;

	/* wakeups per 100ms = (100ms / interval) */
	new_freq = (100ULL * 1000000ULL) / interval_ns;
	return ewma(freq, new_freq);
}

/* ------------------------------------------------------------------ */
/* Helper: update voluntary ctx switch rate (per sec)                 */
/* ------------------------------------------------------------------ */
static inline u32 update_vol_ctx_rate(u32 old_rate, u64 delta_nvcsw, u64 interval_ns)
{
	u64 per_sec;

	if (interval_ns == 0)
		interval_ns = 1;

	/* per_sec = delta * 1s / interval */
	per_sec = (delta_nvcsw * 1000000000ULL) / interval_ns;
	if (per_sec > 0xffffffffULL)
		per_sec = 0xffffffffULL;

	return (u32)ewma(old_rate, (u32)per_sec);
}

/* ------------------------------------------------------------------ */
/* Helper: apply tier rule (force or min)                             */
/* ------------------------------------------------------------------ */
static inline void apply_tier_rule(const struct tier_rule *rule,
				   u8 *min_tier, u8 *force_tier, u8 *force_valid)
{
	if (!rule)
		return;
	if (rule->mode == TIER_RULE_FORCE) {
		*force_tier = rule->tier;
		*force_valid = 1;
	} else if (rule->mode == TIER_RULE_MIN) {
		if (rule->tier > *min_tier)
			*min_tier = rule->tier;
	}
}

/* ------------------------------------------------------------------ */
/* Helper: LP-only mode state with hysteresis                         */
/* ------------------------------------------------------------------ */
static inline u64 *lp_only_state_ptr(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&lp_only_state_map, &key);
}

static inline void update_lp_only_state(void)
{
	u32 load_pct;
	u32 nr_cpus = (u32)nr_cpu_ids;
	u64 *statep = lp_only_state_ptr();
	u32 q_lp = 0, q_e = 0, q_p = 0;
	u64 runnable;
	u64 prev_state;
	u64 new_state;

	if (!statep)
		return;

	if (nr_lp_cpus == 0 || nr_cpus == 0) {
		*statep = 0;
		return;
	}

	q_lp = scx_bpf_dsq_nr_queued(DSQ_LP);
	q_e = scx_bpf_dsq_nr_queued(DSQ_E);
	q_p = scx_bpf_dsq_nr_queued(DSQ_P);
	runnable = nr_running + (u64)q_lp + (u64)q_e + (u64)q_p;
	load_pct = (u32)((runnable * 100ULL) / nr_cpus);

	prev_state = *statep;
	new_state = prev_state;

	if (!new_state) {
		if (load_pct <= lp_only_load_pct)
			new_state = 1;
	} else {
		if (load_pct >= (lp_only_load_pct + lp_only_hyst_pct))
			new_state = 0;
	}

	if (new_state != prev_state) {
		*statep = new_state;
		dbg("meteor: lp_only=%llu load=%u running=%llu q_lp=%u q_e=%u q_p=%u",
		    new_state, load_pct, nr_running, q_lp, q_e, q_p);
	}
}

static inline bool lp_only_active(void)
{
	u64 *statep = lp_only_state_ptr();

	if (!statep)
		return false;
	return *statep != 0;
}

/* ------------------------------------------------------------------ */
/* Helper: read HFI caps for CPU                                      */
/* ------------------------------------------------------------------ */
static inline struct hfi_caps *get_hfi_caps(s32 cpu)
{
	u32 key = (u32)cpu;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&hfi_caps_map, &key);
}

/* ------------------------------------------------------------------ */
/* Task context helpers                                                */
/* ------------------------------------------------------------------ */
static struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

/* ------------------------------------------------------------------ */
/* DSQ helpers                                                         */
/* ------------------------------------------------------------------ */
static inline u64 cpu_dsq(s32 cpu)
{
	return DSQ_CPU_BASE + (u64)cpu;
}

/* Map task tier to shared DSQ id */
static inline u64 tier_dsq(u8 tier)
{
	switch (tier) {
	case TIER_LP: return DSQ_LP;
	case TIER_E:  return DSQ_E;
	default:      return DSQ_P;
	}
}

/* ------------------------------------------------------------------ */
/* Core-type helpers                                                   */
/* ------------------------------------------------------------------ */
static inline u8 get_cpu_core_type(s32 cpu)
{
	u32 idx = (u32)cpu;

	if (idx >= MAX_CPUS)
		return CORE_E;  /* safe default */
	return cpu_core_type[idx];
}

/* ------------------------------------------------------------------ */
/* Find idle CPU in a tier's cpu list                                 */
/* Tries prev_cpu first if it matches expected_core_type, then scans. */
/* Returns ≥ 0 on success, -EBUSY if no idle CPU found.               */
/* ------------------------------------------------------------------ */
static s32 pick_idle_cpu_in_list(struct task_struct *p, s32 prev_cpu,
				 const volatile u32 *cpu_list, u32 nr_list,
				 u8 expected_core_type)
{
	u32 max_iter = MIN(nr_list, (u32)MAX_CPUS);
	s32 first_idle = -EBUSY;
	s32 best_cpu = -EBUSY;
	u32 best_score = 0;
	bool any_hfi = false;
	int i;

	/*
	 * Try prev_cpu first for cache locality — use core type to check
	 * tier membership (O(1) vs O(n) list scan).
	 */
	if (prev_cpu >= 0 && prev_cpu < MAX_CPUS &&
	    cpu_core_type[prev_cpu] == expected_core_type &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
	}

	/* Scan the tier's CPU list for any idle CPU */
	bpf_for(i, 0, max_iter) {
		s32 cpu = (s32)cpu_list[i];
		struct hfi_caps *hc;
		u32 score = 0;

		if (cpu < 0 || cpu >= MAX_CPUS)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			goto consider_cpu;
		continue;

consider_cpu:
		if (first_idle < 0)
			first_idle = cpu;

		hc = get_hfi_caps(cpu);
		if (hc && hc->valid) {
			any_hfi = true;
			score = (expected_core_type == CORE_LP) ? hc->eff : hc->perf;
			if (score > best_score) {
				best_score = score;
				best_cpu = cpu;
			}
		}
	}

	if (any_hfi && best_cpu >= 0)
		return best_cpu;
	if (first_idle >= 0)
		return first_idle;
	return -EBUSY;
}

/* ------------------------------------------------------------------ */
/* Determine initial tier and rule-based constraints                  */
/* Priority: comm/cgroup rules → procdb → sched_policy → nice → LP   */
/* ------------------------------------------------------------------ */
static void init_task_policy(struct task_struct *p, struct task_ctx *tctx)
{
	struct proc_profile *profile;
	struct tier_rule *rule;
	char comm[PROC_COMM_LEN];
	u8 min_tier = TIER_LP;
	u8 force_tier = 0;
	u8 force_valid = 0;
	u8 tier = TIER_LP;
	int policy = p->policy;
	int nice   = TASK_NICE(p);
	u64 cg_id;

	/* 1. Kernel threads → E-core (kernel work should be reliable) */
	if (p->flags & PF_KTHREAD)
		min_tier = TIER_E;

	/* 2. Per-comm rules */
	__builtin_memcpy(comm, p->comm, PROC_COMM_LEN);
	rule = bpf_map_lookup_elem(&comm_rules, comm);
	apply_tier_rule(rule, &min_tier, &force_tier, &force_valid);

	/* 3. Per-cgroup rules */
	cg_id = bpf_get_current_cgroup_id();
	rule = bpf_map_lookup_elem(&cgroup_rules, &cg_id);
	apply_tier_rule(rule, &min_tier, &force_tier, &force_valid);

	/* If forced, lock tier and return */
	if (force_valid) {
		tctx->tier = force_tier;
		tctx->min_tier = force_tier;
		tctx->force_tier = force_tier;
		tctx->force_valid = 1;
		return;
	}

	/* 4. Check procdb for this process name */
	profile = bpf_map_lookup_elem(&proc_profiles, comm);
	if (profile && profile->confidence >= procdb_confidence_min) {
		__sync_fetch_and_add(&nr_procdb_hits, 1);
		tctx->procdb_loaded = 1;
		tier = profile->tier;
		goto out;
	}

	/* 5. Scheduling policy: IDLE/BATCH → LP always */
	if (policy == SCHED_IDLE || policy == SCHED_BATCH)
		tier = TIER_LP;

	/* 6. Nice value: high nice → background → LP */
	else if (nice >= 10)
		tier = TIER_LP;
	else if (nice > 0)
		tier = TIER_E;

	/* 7. Apple-style default: start on LP E-core */
	else
		tier = TIER_LP;

out:
	if (tier < min_tier)
		tier = min_tier;

	tctx->tier = tier;
	tctx->min_tier = min_tier;
	tctx->force_tier = force_tier;
	tctx->force_valid = 0;
}

/* ------------------------------------------------------------------ */
/* Publish a task's profile to the observation map (for Rust to save) */
/* ------------------------------------------------------------------ */
static void publish_observation(struct task_struct *p, struct task_ctx *tctx)
{
	struct proc_profile obs = {
		.tier             = tctx->tier,
		.confidence       = (u8)MIN(tctx->observations, 100),
		.vol_ctx_per_sec  = tctx->vol_ctx_per_sec,
		.wakeups_per_sec  = (u32)MIN(tctx->wakeup_freq * 10, 0xffffffffULL),
		.observations     = tctx->observations,
		.avg_burst_ns     = tctx->avg_burst_ns,
		.avg_sleep_ns     = tctx->avg_sleep_ns,
		.total_runtime_ns = tctx->total_runtime_ns,
		.last_seen_ns     = bpf_ktime_get_ns(),
	};
	char comm[PROC_COMM_LEN];

	__builtin_memcpy(comm, p->comm, PROC_COMM_LEN);
	bpf_map_update_elem(&procdb_observations, comm, &obs, BPF_ANY);
}

/* ------------------------------------------------------------------ */
/* Check burst escalation / drain-back after task stops running       */
/* ------------------------------------------------------------------ */
static void update_tier(struct task_struct *p, struct task_ctx *tctx,
			u64 burst_ns, u64 now)
{
	u8 old_tier = tctx->tier;
	u8 new_tier = old_tier;
	u64 burst_for_escalation = tctx->avg_burst_ns;
	bool interactive = false;

	if (tctx->force_valid) {
		tctx->tier = tctx->force_tier;
		return;
	}

	if (tctx->first_run_at &&
	    now - tctx->first_run_at <= fast_burst_window_ns)
		burst_for_escalation = burst_ns;

	/* Interactive detection: short bursts + high wakeups/ctx-switches */
	if (tctx->wakeup_freq >= interactive_wakeup_freq ||
	    tctx->vol_ctx_per_sec >= interactive_csw_rate ||
	    (burst_ns > 0 && burst_ns <= interactive_short_burst_ns &&
	     tctx->wakeup_freq >= (interactive_wakeup_freq / 2)))
		interactive = true;
	if (tctx->sync_wake)
		interactive = true;

	/* Track bursty pattern within a window */
	if (burst_for_escalation > lp_burst_thresh_ns) {
		if (tctx->bursty_window_start == 0 ||
		    now - tctx->bursty_window_start > bursty_window_ns) {
			tctx->bursty_window_start = now;
			tctx->bursty_count = 0;
		}
		tctx->bursty_count++;
		if (tctx->bursty_count >= bursty_threshold)
			tctx->bursty_until = now + bursty_hold_ns;
	}

	/* Escalation: task is CPU-hungry → move up */
	if (old_tier == TIER_LP) {
		if (burst_for_escalation > lp_burst_thresh_ns)
			tctx->burst_streak_lp++;
		else
			tctx->burst_streak_lp = 0;

		if (tctx->burst_streak_lp >= burst_up_streak) {
			/* High wakeup freq / ctx rate = interactive on P; otherwise E */
			new_tier = (interactive &&
				    (tctx->wakeup_freq >= interactive_wakeup_freq * 2 ||
			     tctx->vol_ctx_per_sec >= interactive_csw_rate * 2))
			   ? TIER_P : TIER_E;
			dbg("meteor: escalate %s LP→%d burst=%llu", p->comm,
			    new_tier, burst_for_escalation);
		}
	} else if (old_tier == TIER_E) {
		if (burst_for_escalation > e_burst_thresh_ns)
			tctx->burst_streak_e++;
		else
			tctx->burst_streak_e = 0;

		if (tctx->burst_streak_e >= burst_up_streak) {
			new_tier = TIER_P;
			dbg("meteor: escalate %s E→P burst=%llu", p->comm,
			    burst_for_escalation);
		}
	}

	/* Interactive promotion even without long bursts */
	if (old_tier == TIER_LP && interactive && tctx->observations > 10) {
		if (new_tier < TIER_E)
			new_tier = TIER_E;
		__sync_fetch_and_add(&nr_interactive_promos, 1);
	}

	/* CPU-bound demotion (degradable priorities) */
	if (burst_for_escalation >= cpu_bound_burst_ns &&
	    tctx->wakeup_freq < (interactive_wakeup_freq / 2)) {
		tctx->cpu_bound_ns += burst_ns;
	} else if (tctx->cpu_bound_ns > burst_ns) {
		tctx->cpu_bound_ns -= burst_ns;
	} else {
		tctx->cpu_bound_ns = 0;
	}

	if (tctx->cpu_bound_ns >= cpu_bound_total_ns && new_tier > TIER_LP) {
		new_tier = (u8)(new_tier - 1);
		tctx->cpu_bound_ns = 0;
		__sync_fetch_and_add(&nr_cpu_bound_demotes, 1);
		dbg("meteor: cpu-bound demote %s %d→%d", p->comm,
		    old_tier, new_tier);
	}

	/* Reset quiet clock if still bursty */
	if (burst_for_escalation > lp_burst_thresh_ns / 4)
		tctx->last_quiet_at = 0;  /* not quiet yet */
	else if (tctx->last_quiet_at == 0)
		tctx->last_quiet_at = now;

	/* Drain-back: task has been quiet long enough → move back to LP */
	if (old_tier > TIER_LP && tctx->last_quiet_at > 0 &&
	    now - tctx->last_quiet_at > drain_delay_ns) {
		new_tier = (u8)(old_tier - 1);
		tctx->last_quiet_at = now;  /* reset for next stage */
		dbg("meteor: drain-back %s %d→%d", p->comm, old_tier, new_tier);
	}

	/* Bursty pattern: keep at least E while in bursty hold window */
	if (new_tier < TIER_E && now < tctx->bursty_until)
		new_tier = TIER_E;

	/* Respect minimum tier rule */
	if (new_tier < tctx->min_tier)
		new_tier = tctx->min_tier;

	if (new_tier != old_tier) {
		tctx->tier = new_tier;
		tctx->burst_streak_lp = 0;
		tctx->burst_streak_e = 0;
		if (new_tier > old_tier)
			__sync_fetch_and_add(&nr_escalations, 1);
		else
			__sync_fetch_and_add(&nr_drainbacks, 1);

		/* Publish to Rust for persistence when confidence is high */
		if (tctx->observations >= procdb_confidence_min)
			publish_observation(p, tctx);
	}

	tctx->sync_wake = 0;
}

/* ------------------------------------------------------------------ */
/* ops.select_cpu() — fast path: find idle CPU and dispatch directly  */
/* ------------------------------------------------------------------ */
s32 BPF_STRUCT_OPS(meteor_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	u8 tier;
	s32 cpu = -EBUSY;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	if (wake_flags & SCX_WAKE_SYNC)
		tctx->sync_wake = 1;

	update_lp_only_state();
	tier = tctx->tier;
	if (lp_only_active() && nr_lp_cpus > 0) {
		tier = TIER_LP;
		__sync_fetch_and_add(&nr_lp_only_forced, 1);
	}

	/*
	 * Tier-based CPU selection with fallback chain:
	 *   TIER_LP → try LP E-cores only  (keep Compute tile OFF)
	 *   TIER_E  → try E-cores, fallback to P if available
	 *   TIER_P  → try P-cores, fallback to E-cores
	 */
	switch (tier) {
	case TIER_LP:
		cpu = pick_idle_cpu_in_list(p, prev_cpu, lp_cpus, nr_lp_cpus, CORE_LP);
		/* No fallback: LP tasks wait for LP cores → Compute tile stays off */
		break;

	case TIER_E:
		cpu = pick_idle_cpu_in_list(p, prev_cpu, e_cpus, nr_e_cpus, CORE_E);
		if (cpu < 0)
			/* Overflow to P if all E are busy */
			cpu = pick_idle_cpu_in_list(p, prev_cpu, p_cpus, nr_p_cpus, CORE_P);
		break;

	case TIER_P:
		cpu = pick_idle_cpu_in_list(p, prev_cpu, p_cpus, nr_p_cpus, CORE_P);
		if (cpu < 0)
			cpu = pick_idle_cpu_in_list(p, prev_cpu, e_cpus, nr_e_cpus, CORE_E);
		break;
	}

	if (cpu >= 0) {
		/* Direct dispatch to per-CPU DSQ — bypasses ops.enqueue() */
		scx_bpf_dsq_insert(p, cpu_dsq(cpu), slice_ns, wake_flags);
		u8 core_type = get_cpu_core_type(cpu);
		switch (core_type) {
		case CORE_LP: __sync_fetch_and_add(&nr_lp_direct, 1); break;
		case CORE_E:  __sync_fetch_and_add(&nr_e_direct, 1);  break;
		default:      __sync_fetch_and_add(&nr_p_direct, 1);  break;
		}
		return cpu;
	}

	return prev_cpu;
}

/* ------------------------------------------------------------------ */
/* ops.enqueue() — tasks that didn't get a direct CPU in select_cpu() */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u8 tier;
	u64 dsq;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		update_lp_only_state();
		if (lp_only_active() && nr_lp_cpus > 0) {
			scx_bpf_dsq_insert(p, DSQ_LP, slice_ns, enq_flags);
			__sync_fetch_and_add(&nr_lp_only_forced, 1);
		} else {
			scx_bpf_dsq_insert(p, DSQ_E, slice_ns, enq_flags);
		}
		return;
	}

	/* Per-CPU kthreads: dispatch directly to their CPU */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	update_lp_only_state();
	tier = tctx->tier;
	if (lp_only_active() && nr_lp_cpus > 0) {
		tier = TIER_LP;
		__sync_fetch_and_add(&nr_lp_only_forced, 1);
	}
	dsq  = tier_dsq(tier);

	scx_bpf_dsq_insert(p, dsq, slice_ns, enq_flags);

	switch (tier) {
	case TIER_LP: __sync_fetch_and_add(&nr_lp_shared, 1); break;
	case TIER_E:  __sync_fetch_and_add(&nr_e_shared, 1);  break;
	default:      __sync_fetch_and_add(&nr_p_shared, 1);  break;
	}

	/* Wake an appropriate CPU if it's idle */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		s32 prev_cpu = scx_bpf_task_cpu(p);
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
	}
}

/* ------------------------------------------------------------------ */
/* ops.dispatch() — called by each CPU when it runs out of work       */
/* Each CPU serves its own tier's DSQ first, then overflows.          */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_dispatch, s32 cpu, struct task_struct *prev)
{
	u8 core_type;

	/* 1. Per-CPU DSQ (direct dispatches from select_cpu) */
	if (scx_bpf_dsq_move_to_local(cpu_dsq(cpu)))
		return;

	core_type = get_cpu_core_type(cpu);

	if (lp_only_active() && core_type != CORE_LP)
		return;

	/* 2. Primary shared DSQ for this core type */
	switch (core_type) {
	case CORE_LP:
		if (scx_bpf_dsq_move_to_local(DSQ_LP))
			return;
		if (lp_only_active()) {
			/* Drain non-LP DSQs when in LP-only mode */
			if (scx_bpf_dsq_move_to_local(DSQ_E))
				return;
			if (scx_bpf_dsq_move_to_local(DSQ_P))
				return;
		} else if (lp_can_help_e) {
			if (scx_bpf_dsq_move_to_local(DSQ_E))
				return;
		}
		break;

	case CORE_E:
		if (scx_bpf_dsq_move_to_local(DSQ_E))
			return;
		/* E-cores serve P-tier tasks if P-cores are busy */
		if (scx_bpf_dsq_move_to_local(DSQ_P))
			return;
		if (!strict_lp) {
			/* Anti-starvation: steal from LP DSQ if enabled */
			if (scx_bpf_dsq_move_to_local(DSQ_LP))
				return;
		}
		break;

	case CORE_P:
		if (scx_bpf_dsq_move_to_local(DSQ_P))
			return;
		if (scx_bpf_dsq_move_to_local(DSQ_E))
			return;
		if (!strict_lp) {
			/* Anti-starvation: steal from LP DSQ as last resort */
			if (scx_bpf_dsq_move_to_local(DSQ_LP))
				return;
		}
		break;
	}

	/* 3. Keep running the previous task if nothing else is available */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = slice_ns;
}

/* ------------------------------------------------------------------ */
/* ops.running() — task starts executing on a CPU                     */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);
	update_lp_only_state();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_run_at = bpf_ktime_get_ns();
	if (tctx->first_run_at == 0)
		tctx->first_run_at = tctx->last_run_at;

	/* Keep global vtime advancing */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/* ------------------------------------------------------------------ */
/* ops.stopping() — task stops (voluntarily or preempted)             */
/* Update burst stats and check for tier escalation/drain-back.       */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now, burst_ns, delta_vtime;
	u64 nvcsw, delta_nvcsw, delta_t;

	__sync_fetch_and_sub(&nr_running, 1);
	update_lp_only_state();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	now      = bpf_ktime_get_ns();
	burst_ns = (now > tctx->last_run_at) ? now - tctx->last_run_at : 0;

	/* Update burst EWMA */
	tctx->avg_burst_ns = ewma(tctx->avg_burst_ns, burst_ns);
	tctx->observations++;
	tctx->total_runtime_ns += burst_ns;

	/* Update voluntary ctx switch rate */
	nvcsw = p->nvcsw;
	if (tctx->last_nvcsw_at > 0) {
		delta_nvcsw = (nvcsw > tctx->last_nvcsw) ? (nvcsw - tctx->last_nvcsw) : 0;
		delta_t = (now > tctx->last_nvcsw_at) ? (now - tctx->last_nvcsw_at) : 1;
		tctx->vol_ctx_per_sec = update_vol_ctx_rate(tctx->vol_ctx_per_sec,
						    delta_nvcsw, delta_t);
	}
	tctx->last_nvcsw = nvcsw;
	tctx->last_nvcsw_at = now;

	/* Update vruntime (for fairness accounting) */
	delta_vtime = scale_by_task_weight_inverse(p, burst_ns);
	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;

	/* Publish observation to Rust every 32 scheduling cycles */
	if ((tctx->observations & 0x1f) == 0)
		publish_observation(p, tctx);

	/* Check if tier should change */
	update_tier(p, tctx, burst_ns, now);

	/* Publish on exit if possible */
	if ((p->flags & PF_EXITING) || p->exit_state)
		publish_observation(p, tctx);
}

/* ------------------------------------------------------------------ */
/* ops.runnable() — task becomes runnable (woke up from sleep)        */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now, delta_t, sleep_ns;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	now = bpf_ktime_get_ns();

	/* Reset awake vruntime on each wakeup (new sleep cycle) */
	tctx->awake_vtime = 0;

	/* Update sleep EWMA */
	if (tctx->last_sleep_at > 0) {
		sleep_ns = now - tctx->last_sleep_at;
		tctx->avg_sleep_ns = ewma(tctx->avg_sleep_ns, sleep_ns);
		tctx->last_sleep_at = 0;
	}

	/* Update wakeup frequency */
	delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq = update_wakeup_freq(tctx->wakeup_freq, delta_t);
	tctx->last_woke_at = now;

	/*
	 * High-frequency wakers that are on LP → bump to E
	 * (they're interactive enough that Compute tile wake is worth it)
	 */
	if (tctx->tier == TIER_LP &&
	    tctx->wakeup_freq >= interactive_wakeup_freq &&
	    tctx->observations > 10 &&
	    !tctx->force_valid) {
		dbg("meteor: interactive promote %s LP→E wfreq=%llu",
		    p->comm, tctx->wakeup_freq);
		tctx->tier = (tctx->min_tier > TIER_E) ? tctx->min_tier : TIER_E;
		__sync_fetch_and_add(&nr_escalations, 1);
		__sync_fetch_and_add(&nr_interactive_promos, 1);
	}
}

/* ------------------------------------------------------------------ */
/* ops.quiescent() — task goes to sleep                               */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_sleep_at = bpf_ktime_get_ns();

	/* Decay CPU-bound accumulator on sleep */
	if (tctx->cpu_bound_ns > 0)
		tctx->cpu_bound_ns >>= 1;
}

/* ------------------------------------------------------------------ */
/* ops.enable() — called when sched_ext starts managing a task        */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Assign initial tier from procdb / policy heuristics */
	init_task_policy(p, tctx);

	/* Initialize vruntime to current global value */
	p->scx.dsq_vtime = vtime_now;
}

/* ------------------------------------------------------------------ */
/* ops.init_task() — allocate per-task context                        */
/* ------------------------------------------------------------------ */
s32 BPF_STRUCT_OPS(meteor_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
			    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/* Zero-initialize */
	tctx->tier          = TIER_LP;
	tctx->min_tier      = TIER_LP;
	tctx->force_tier    = 0;
	tctx->force_valid   = 0;
	tctx->sync_wake     = 0;
	tctx->last_run_at   = 0;
	tctx->first_run_at  = 0;
	tctx->avg_burst_ns  = 0;
	tctx->avg_sleep_ns  = 0;
	tctx->total_runtime_ns = 0;
	tctx->last_quiet_at = 0;
	tctx->last_woke_at  = 0;
	tctx->wakeup_freq   = 0;
	tctx->awake_vtime   = 0;
	tctx->last_sleep_at = 0;
	tctx->last_nvcsw_at = 0;
	tctx->last_nvcsw    = 0;
	tctx->cpu_bound_ns  = 0;
	tctx->bursty_until  = 0;
	tctx->observations  = 0;
	tctx->vol_ctx_per_sec = 0;
	tctx->burst_streak_lp = 0;
	tctx->burst_streak_e  = 0;
	tctx->bursty_count    = 0;
	tctx->bursty_window_start = 0;
	tctx->procdb_loaded = 0;

	return 0;
}

/* ------------------------------------------------------------------ */
/* ops.init() — scheduler initialization (sleepable context)          */
/* ------------------------------------------------------------------ */
s32 BPF_STRUCT_OPS_SLEEPABLE(meteor_init)
{
	int err, i;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Create per-CPU DSQs (one per possible CPU) */
	bpf_for(i, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu_dsq(i), -1);
		if (err) {
			scx_bpf_error("failed to create per-CPU DSQ %llu: %d",
				      cpu_dsq(i), err);
			return err;
		}
	}

	/* Create shared tier DSQs */
	err = scx_bpf_create_dsq(DSQ_LP, -1);
	if (err) {
		scx_bpf_error("failed to create DSQ_LP: %d", err);
		return err;
	}

	err = scx_bpf_create_dsq(DSQ_E, -1);
	if (err) {
		scx_bpf_error("failed to create DSQ_E: %d", err);
		return err;
	}

	err = scx_bpf_create_dsq(DSQ_P, -1);
	if (err) {
		scx_bpf_error("failed to create DSQ_P: %d", err);
		return err;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* ops.exit() — scheduler teardown                                    */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(meteor_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* ------------------------------------------------------------------ */
/* Define the scheduler ops struct                                     */
/* ------------------------------------------------------------------ */
SCX_OPS_DEFINE(meteor_ops,
	       .select_cpu  = (void *)meteor_select_cpu,
	       .enqueue     = (void *)meteor_enqueue,
	       .dispatch    = (void *)meteor_dispatch,
	       .running     = (void *)meteor_running,
	       .stopping    = (void *)meteor_stopping,
	       .runnable    = (void *)meteor_runnable,
	       .quiescent   = (void *)meteor_quiescent,
	       .enable      = (void *)meteor_enable,
	       .init_task   = (void *)meteor_init_task,
	       .init        = (void *)meteor_init,
	       .exit        = (void *)meteor_exit,
	       .timeout_ms  = 5000,
	       .name        = "meteor");
