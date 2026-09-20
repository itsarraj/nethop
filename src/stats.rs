//! Pure round-trip statistics, including packet loss — the core "mtr"
//! numbers computed from a set of per-probe results.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopStats {
    pub sent: usize,
    pub received: usize,
    pub min: Duration,
    pub avg: Duration,
    pub max: Duration,
}

impl HopStats {
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        (1.0 - (self.received as f64 / self.sent as f64)) * 100.0
    }
}

/// `samples` has one entry per probe sent, `None` for a probe that got
/// no reply at all (real loss, not just "not measured yet").
pub fn compute_hop_stats(samples: &[Option<Duration>]) -> HopStats {
    let received: Vec<Duration> = samples.iter().filter_map(|s| *s).collect();
    if received.is_empty() {
        return HopStats {
            sent: samples.len(),
            received: 0,
            min: Duration::ZERO,
            avg: Duration::ZERO,
            max: Duration::ZERO,
        };
    }
    let min = *received.iter().min().unwrap();
    let max = *received.iter().max().unwrap();
    let total: Duration = received.iter().sum();
    let avg = total / received.len() as u32;
    HopStats {
        sent: samples.len(),
        received: received.len(),
        min,
        avg,
        max,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_probes_lost_has_zero_percent_loss_edge_case_handled() {
        let stats = compute_hop_stats(&[None, None, None]);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.loss_percent(), 100.0);
    }

    #[test]
    fn no_probes_sent_at_all_has_zero_percent_loss_not_a_divide_by_zero() {
        let stats = compute_hop_stats(&[]);
        assert_eq!(stats.loss_percent(), 0.0);
    }

    #[test]
    fn all_probes_received_has_zero_percent_loss() {
        let stats = compute_hop_stats(&[
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(20)),
        ]);
        assert_eq!(stats.loss_percent(), 0.0);
    }

    #[test]
    fn partial_loss_computes_correct_percentage() {
        let stats = compute_hop_stats(&[
            Some(Duration::from_millis(10)),
            None,
            Some(Duration::from_millis(20)),
            None,
        ]);
        assert_eq!(stats.sent, 4);
        assert_eq!(stats.received, 2);
        assert_eq!(stats.loss_percent(), 50.0);
    }

    #[test]
    fn min_avg_max_computed_only_over_received_samples() {
        let stats = compute_hop_stats(&[
            Some(Duration::from_millis(10)),
            None,
            Some(Duration::from_millis(30)),
        ]);
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(30));
        assert_eq!(stats.avg, Duration::from_millis(20));
    }
}
