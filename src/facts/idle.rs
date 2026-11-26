//! Idle: how long a process's whole subtree has done no work.
//!
//! Each scan, every process contributes the CPU and disk it used since the previous scan; a
//! subtree is active when the sum over its members passes a fixed rate. CPU counts the
//! process's own time plus that of its reaped children, so a test runner that forks a short
//! worker per test stays active even though no worker lives across two scans.

use std::collections::HashMap;
use std::ops::AddAssign;
use std::time::Duration;

use crate::facts::ProcKey;
use crate::facts::table::ProcessTable;
use crate::platform::Usage;

/// A subtree using more CPU than this per second of wall time is active: 0.5 % of a core.
///
/// Measured on this machine (Apple Silicon, macOS 26) on 2026-11-26, whole subtree, 5 s
/// windows, 30 windows each:
/// - headless Chrome for Testing 159 (Playwright `chromium-1255`, `--headless=new
///   --remote-debugging-port=0 about:blank`, 10 processes), 1-3 min after launch:
///   0.29-2.19 ms/s, with one-off startup bursts of 10-39 ms/s at about 25 s and 60 s;
/// - `bun` 1.4.5 running `setInterval(() => {}, 1e6)`: 0.84-0.99 ms/s in its first 20 s,
///   then 0.00-0.25 ms/s.
///
/// 5 ms/s is over twice the highest idle sample.
const ACTIVE_CPU_PER_SEC: Duration = Duration::from_millis(5);

/// A subtree reading or writing more than this per second is active: 1 MiB/s.
///
/// Measured with the CPU samples above: idle Chrome 2.4-42 KiB/s, once 177 KiB/s (its
/// profile flushes), and 2.8 MiB/s in its 39 ms/s startup burst; idle `bun` 0 B/s. 64 KiB/s
/// would have counted idle Chrome as active.
const ACTIVE_DISK_PER_SEC: u64 = 1024 * 1024;

/// The work one process, or one subtree, did in a scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Activity {
    cpu: Duration,
    disk: u64,
    /// A member's counters could not be read: unknown counts as active.
    unknown: bool,
}

impl Activity {
    /// Everything a process did since it started: for a process first seen this scan.
    pub(crate) fn full(now: Option<Usage>) -> Self {
        Self::delta(Some(ZERO_USAGE), now)
    }

    /// What a process did between two readings of its counters. A counter that went down
    /// (`exec` resets the reaped-children CPU) contributes nothing rather than counting as
    /// work.
    pub(crate) fn delta(prev: Option<Usage>, now: Option<Usage>) -> Self {
        let (Some(prev), Some(now)) = (prev, now) else {
            return Self {
                unknown: true,
                ..Self::default()
            };
        };
        Self {
            cpu: now.cpu.saturating_sub(prev.cpu)
                + now.children_cpu.saturating_sub(prev.children_cpu),
            disk: disk_total(now).saturating_sub(disk_total(prev)),
            unknown: false,
        }
    }

    /// Whether this much work over `interval` makes the subtree active. Without an interval
    /// (the first scan) everything is active.
    pub(crate) fn is_active(&self, interval: Option<Duration>) -> bool {
        let Some(interval) = interval else {
            return true;
        };
        self.unknown
            || self.cpu > ACTIVE_CPU_PER_SEC.mul_f64(interval.as_secs_f64())
            || u128::from(self.disk) * 1000 > u128::from(ACTIVE_DISK_PER_SEC) * interval.as_millis()
    }

    fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

impl AddAssign for Activity {
    fn add_assign(&mut self, other: Self) {
        self.cpu += other.cpu;
        self.disk = self.disk.saturating_add(other.disk);
        self.unknown |= other.unknown;
    }
}

const ZERO_USAGE: Usage = Usage {
    cpu: Duration::ZERO,
    children_cpu: Duration::ZERO,
    disk_read: 0,
    disk_written: 0,
};

fn disk_total(usage: Usage) -> u64 {
    usage.disk_read.saturating_add(usage.disk_written)
}

/// Sums each process's own activity into itself and every ancestor.
pub(crate) fn subtree_activity(
    table: &ProcessTable,
    own: &HashMap<ProcKey, Activity>,
) -> HashMap<ProcKey, Activity> {
    let mut sums: HashMap<ProcKey, Activity> = HashMap::new();
    for process in table.iter() {
        let Some(activity) = own.get(&process.key()).filter(|a| !a.is_zero()) else {
            continue;
        };
        for member in std::iter::once(process).chain(table.ancestors_of(process)) {
            *sums.entry(member.key()).or_default() += *activity;
        }
    }
    sums
}

/// The process's own CPU over the last scan, in percent of one core; `None` without two
/// readings.
pub(crate) fn cpu_percent(
    prev: Option<Usage>,
    now: Option<Usage>,
    interval: Option<Duration>,
) -> Option<f64> {
    let interval = interval.filter(|i| !i.is_zero())?;
    let used = now?.cpu.saturating_sub(prev?.cpu);
    Some(used.as_secs_f64() / interval.as_secs_f64() * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(cpu_ms: u64, children_ms: u64, disk: u64) -> Option<Usage> {
        Some(Usage {
            cpu: Duration::from_millis(cpu_ms),
            children_cpu: Duration::from_millis(children_ms),
            disk_read: disk,
            disk_written: 0,
        })
    }

    const SCAN: Option<Duration> = Some(Duration::from_secs(5));

    #[test]
    fn exec_resetting_reaped_children_cpu_is_not_activity() {
        let activity = Activity::delta(usage(100, 5000, 0), usage(100, 0, 0));
        assert_eq!(activity, Activity::default());
        assert!(!activity.is_active(SCAN));
    }

    #[test]
    fn reaped_children_cpu_counts() {
        assert!(Activity::delta(usage(100, 0, 0), usage(100, 200, 0)).is_active(SCAN));
    }

    #[test]
    fn disk_alone_makes_a_process_active() {
        let activity = Activity::delta(usage(0, 0, 0), usage(0, 0, 10 << 20));
        assert!(activity.is_active(SCAN));
    }

    #[test]
    fn unknown_counters_are_active() {
        assert!(Activity::delta(None, usage(0, 0, 0)).is_active(SCAN));
        assert!(Activity::delta(usage(0, 0, 0), None).is_active(SCAN));
    }

    #[test]
    fn the_threshold_scales_with_the_interval() {
        // 10 ms over 5 s is 2 ms/s: idle. The same 10 ms over 1 s is active.
        let activity = Activity::delta(usage(0, 0, 0), usage(10, 0, 0));
        assert!(!activity.is_active(SCAN));
        assert!(activity.is_active(Some(Duration::from_secs(1))));
        assert!(activity.is_active(None));
    }

    #[test]
    fn cpu_percent_is_own_cpu_over_the_interval() {
        let pct = cpu_percent(usage(1000, 9000, 0), usage(3500, 0, 0), SCAN).unwrap();
        assert!((pct - 50.0).abs() < 1e-9);
        assert_eq!(cpu_percent(None, usage(1, 0, 0), SCAN), None);
        assert_eq!(cpu_percent(usage(0, 0, 0), usage(1, 0, 0), None), None);
    }
}
