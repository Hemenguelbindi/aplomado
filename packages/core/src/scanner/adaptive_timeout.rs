use std::time::Duration;

pub struct AdaptiveTimeouts {
    initial_connect_timeout: Duration,
    connect_timeout_max: Duration,
    ping_timeout: Duration,
    rtt_samples: Vec<Duration>,
    max_rtt_samples: usize,
}

impl AdaptiveTimeouts {
    pub fn new() -> Self {
        Self {
            initial_connect_timeout: Duration::from_secs(3),
            connect_timeout_max: Duration::from_secs(10),
            ping_timeout: Duration::from_secs(3),
            rtt_samples: Vec::with_capacity(10),
            max_rtt_samples: 10,
        }
    }

    pub fn current_connect_timeout(&self) -> Duration {
        let adaptive = self
            .rtt_samples
            .iter()
            .max()
            .map(|rtt| *rtt * 2)
            .unwrap_or(self.initial_connect_timeout)
            .max(Duration::from_millis(500));
        adaptive.min(self.connect_timeout_max)
    }

    pub fn record_rtt(&mut self, rtt: Duration) {
        if rtt > Duration::from_secs(10) {
            return;
        }
        let median = self.rtt_median();
        if self.rtt_samples.len() >= 2 && rtt > median * 3 {
            return;
        }
        if self.rtt_samples.len() >= self.max_rtt_samples {
            self.rtt_samples.remove(0);
        }
        self.rtt_samples.push(rtt);
    }

    fn rtt_median(&self) -> Duration {
        let mut sorted = self.rtt_samples.clone();
        sorted.sort();
        let mid = sorted.len() / 2;
        if sorted.is_empty() {
            Duration::ZERO
        } else if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        }
    }

    pub fn ping_timeout(&self) -> Duration {
        self.ping_timeout
    }
}

impl Default for AdaptiveTimeouts {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rtt_returns_initial() {
        let at = AdaptiveTimeouts::new();
        assert_eq!(at.current_connect_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn single_sample_doubles() {
        let mut at = AdaptiveTimeouts::new();
        at.record_rtt(Duration::from_millis(500));
        assert_eq!(at.current_connect_timeout(), Duration::from_millis(1000));
    }

    #[test]
    fn outlier_rejected() {
        let mut at = AdaptiveTimeouts::new();
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(200));
        at.record_rtt(Duration::from_millis(150));
        at.record_rtt(Duration::from_secs(5));
        assert_eq!(at.rtt_samples.len(), 3);
    }

    #[test]
    fn cap_at_connect_timeout_max() {
        let mut at = AdaptiveTimeouts::new();
        for _ in 0..10 {
            at.record_rtt(Duration::from_secs(6));
        }
        assert_eq!(at.current_connect_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn record_rtt_maintains_window() {
        let mut at = AdaptiveTimeouts::new();
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        at.record_rtt(Duration::from_millis(100));
        assert_eq!(at.rtt_samples.len(), 10);
        assert_eq!(at.rtt_samples[0], Duration::from_millis(100));
        assert_eq!(at.rtt_samples[9], Duration::from_millis(100));
    }

    #[test]
    fn outlier_greater_than_10s_rejected() {
        let mut at = AdaptiveTimeouts::new();
        at.record_rtt(Duration::from_secs(15));
        assert!(at.rtt_samples.is_empty());
    }

    #[test]
    fn rtt_does_not_go_below_minimum() {
        let mut at = AdaptiveTimeouts::new();
        at.record_rtt(Duration::from_millis(10));
        assert_eq!(at.current_connect_timeout(), Duration::from_millis(500));
    }
}
