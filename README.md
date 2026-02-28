# SCX Meteor Lake Fork — Core Ultra 9 185H (i9 185H)

[Русский](#русский)

This is a **fork of SCX (sched_ext)** tailored for Intel Meteor Lake, specifically the **Core Ultra 9 185H**. It implements a 3-tier scheduler aware of LP E-cores (SoC tile), E-cores, and P-cores (Compute tile), with an **LP‑first, burst‑up, drain‑back** strategy and persistent per‑process profiling.

## Build & Run

Build:
```bash
cd scx
cargo build -p scx_meteor
```

Run (example):
```bash
sudo ./target/debug/scx_meteor --stats 1
```

Debug (BPF trace):
```bash
sudo ./target/debug/scx_meteor -D
sudo cat /sys/kernel/tracing/trace_pipe
```
## Overview

### Core tiers
- **LP E-cores (SoC tile)**: low-power island, no L3; best for background and idle work.
- **E-cores (Compute tile)**: general-purpose throughput.
- **P-cores (Compute tile)**: interactive and heavy CPU tasks.

### Policy
- New tasks start on **LP E-cores**.
- Bursts over thresholds **escalate** to E or P.
- Quiet tasks **drain back** to lower tiers.

### Key features
- **LP-only mode** at low system load (keeps Compute tile off).
- **Strict LP mode** to prevent LP-tier tasks from running on E/P cores.
- **Interactive detection** (wakeup freq, ctx-switch rate, sync-wake).
- **CPU-bound demotion** (degradable priorities).
- **Bursty pattern tracking** to avoid ping-pong.
- **Procdb** with on-disk persistence for warm starts.
- **HFI integration** for best CPU selection within a tier.
- **Comm/cgroup overrides** for workload rules.

### Procdb
- Stored at: `~/.config/scx-meteor/profiles.db`

## Scheduler Timeline (ASCII)

```
[T0] | LP  Task starts on LP cores.
--------------------------
     ├ interactive_wakeup_freq (10/100ms): if it wakes a lot, treat as interactive.
     ├ interactive_csw_rate (50/s): if it switches a lot, treat as interactive.
     ├ lp_only_load_pct (10%): below this load, keep everything on LP.
     ├ lp_only_hyst_pct (5%): extra margin before leaving LP-only.
     └ strict_lp (true): don't let LP tasks run on E/P.

[T1] | *LP* Escalate to E cores.
--------------------------
     ├ lp_burst_ms (5ms): burst time to move **LP → E**.
     ├ burst_up_streak (2): how many bursts in a row are needed.
     └ fast_burst_ms (10ms): faster escalation for first-run bursts.

[T2] | *E* Escalate to P cores.
--------------------------
     ├ e_burst_ms (30ms): burst time to move **E → P**.
     └ burst_up_streak (2): how many bursts in a row are needed.

[T3] | *P/E* Drain back down.
--------------------------
     ├ drain_delay_ms (500ms): wait this long before dropping a tier.
     ├ bursty_window_ms (500ms): window to detect bursty patterns.
     ├ bursty_threshold (3): bursts in window to keep tier.
     └ bursty_hold_ms (1000ms): keep ≥E for this long after bursty.
```

## Scheduler Flags (English)

### Scheduling and thresholds
- `-s, --slice-us <MICROSECONDS>`
- `-b, --lp-burst-ms <MILLISECONDS>`
- `-B, --e-burst-ms <MILLISECONDS>`
- `-d, --drain-delay-ms <MILLISECONDS>`
- `-i, --interactive-wakeup-freq <PER-100MS>`

### LP-only and spillover
- `--lp-only-load-pct <PERCENT>`
- `--lp-only-hyst-pct <PERCENT>`
- `--strict-lp <true|false>`
- `--lp-can-help-e <true|false>`

### Burst and interactivity
- `--fast-burst-ms <MILLISECONDS>`
- `--burst-up-streak <N>`
- `--interactive-short-burst-us <MICROSECONDS>`
- `--interactive-csw-rate <PER-SEC>`

### CPU-bound demotion
- `--cpu-bound-burst-ms <MILLISECONDS>`
- `--cpu-bound-total-ms <MILLISECONDS>`

### Bursty pattern tracking
- `--bursty-window-ms <MILLISECONDS>`
- `--bursty-threshold <N>`
- `--bursty-hold-ms <MILLISECONDS>`

### Procdb
- `-c, --procdb-confidence-min <N>`
- `-p, --procdb-save-interval-s <SECONDS>`

### HFI
- `--hfi-poll-ms <MILLISECONDS>`

### Overrides
- `--background-cgroup <PATHS>`
- `--background-cgroup-id <IDS>`
- `--no-lp-comm <COMMS>`
- `--interactive-comm <COMMS>`

### Stats and debug
- `--stats <SECONDS>`
- `--monitor <SECONDS>`
- `-D, --debug`
- `-v, --verbose`
- `-V, --version`
- `--help-stats`

## Русский

Этот репозиторий — **форк SCX (sched_ext)** под Intel Meteor Lake, конкретно **Core Ultra 9 185H**. Планировщик знает о 3 типах ядер и оптимизирован под энергоэффективность на SoC‑tile.


## Сборка и запуск (Русский)

Сборка:
```bash
cd scx
cargo build -p scx_meteor
```

Запуск (пример):
```bash
sudo ./target/debug/scx_meteor --stats 1
```

Отладка (BPF trace):
```bash
sudo ./target/debug/scx_meteor -D
sudo cat /sys/kernel/tracing/trace_pipe
```

### Политика
- Новые задачи стартуют на **LP**.
- При бурстах → **эскалация** на E/P.
- При тишине → **drain‑back** вниз.

### Ключевые фичи
- **LP‑only** при низкой нагрузке.
- **Strict LP** (LP‑задачи не уходят на E/P).
- **Интерактивность** по wakeup/ctx‑switch/sync‑wake.
- **Деградация CPU‑bound**.
- **Анти‑ping‑pong** через bursty‑tracking.
- **Procdb** с сохранением профилей.
- **HFI** для выбора лучшего CPU внутри тира.
- **Правила по comm/cgroup**.

### Procdb
- Путь: `~/.config/scx-meteor/profiles.db`

## Таймлайн параметров (ASCII)

```
[T0] | LP  Задача стартует на LP ядрах.
--------------------------
     ├ interactive_wakeup_freq (10/100мс): если часто просыпается — интерактив.
     ├ interactive_csw_rate (50/с): если много ctx-switch — интерактив.
     ├ lp_only_load_pct (10%): ниже этой нагрузки всё держим на LP.
     ├ lp_only_hyst_pct (5%): запас перед выходом из LP-only.
     └ strict_lp (true): LP‑задачи не уходят на E/P.

[T1] | *LP* Эскалация на E ядра.
--------------------------
     ├ lp_burst_ms (5мс): порог бурста для **LP → E**.
     ├ burst_up_streak (2): сколько подряд бурстов нужно.
     └ fast_burst_ms (10мс): ускоренное окно на первом запуске.

[T2] | *E* Эскалация на P ядра.
--------------------------
     ├ e_burst_ms (30мс): порог бурста для **E → P**.
     └ burst_up_streak (2): сколько подряд бурстов нужно.

[T3] | *P/E* Слив обратно вниз.
--------------------------
     ├ drain_delay_ms (500мс): ждём перед понижением.
     ├ bursty_window_ms (500мс): окно для bursty.
     ├ bursty_threshold (3): бурстов в окне для удержания.
     └ bursty_hold_ms (1000мс): держим ≥E после bursty.
```
