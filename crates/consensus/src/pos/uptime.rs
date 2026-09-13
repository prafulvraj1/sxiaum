use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sxiaum_types::Address;

/// Tracks the block production performance of validators to enforce uptime and liveness rules.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UptimeMonitor {
    /// Maps validator addresses to the number of consecutive missed slots.
    pub missed_slots: HashMap<Address, u64>,
    /// Maps validator addresses to their total lifetime missed slots.
    pub total_missed: HashMap<Address, u64>,
    /// Threshold for consecutive missed slots before a validator is jailed/slashed.
    pub slashing_threshold: u64,
}

impl UptimeMonitor {
    pub fn new(threshold: u64) -> Self {
        Self {
            missed_slots: HashMap::new(),
            total_missed: HashMap::new(),
            slashing_threshold: threshold,
        }
    }

    /// Record a successfully produced block by a validator.
    pub fn record_success(&mut self, validator: &Address) {
        // Reset consecutive misses upon a successful production.
        self.missed_slots.insert(*validator, 0);
    }

    /// Record a missed slot for a validator.
    /// Returns true if the validator has reached or crossed the slashing threshold.
    pub fn record_miss(&mut self, validator: &Address) -> bool {
        let consecutive = self.missed_slots.entry(*validator).or_insert(0);
        *consecutive = consecutive.saturating_add(1);

        let total = self.total_missed.entry(*validator).or_insert(0);
        *total = total.saturating_add(1);

        *consecutive >= self.slashing_threshold
    }

    /// Check if a validator should be penalized based on current uptime metrics.
    pub fn should_slash(&self, validator: &Address) -> bool {
        self.missed_slots.get(validator).copied().unwrap_or(0) >= self.slashing_threshold
    }

    /// Return the consecutive missed slots for a given validator.
    pub fn consecutive_missed(&self, validator: &Address) -> u64 {
        self.missed_slots.get(validator).copied().unwrap_or(0)
    }

    /// Return the total lifetime missed slots for a given validator.
    pub fn total_missed_count(&self, validator: &Address) -> u64 {
        self.total_missed.get(validator).copied().unwrap_or(0)
    }

    /// Reset metrics for a validator (e.g., after they have served a jail sentence or unjailed).
    pub fn reset_validator(&mut self, validator: &Address) {
        self.missed_slots.remove(validator);
    }

    /// Clear all tracked uptime states.
    pub fn clear(&mut self) {
        self.missed_slots.clear();
        self.total_missed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::UptimeMonitor;
    use sxiaum_types::Address;

    #[test]
    fn uptime_monitor_records_success_and_misses() {
        let mut monitor = UptimeMonitor::new(3);
        let val = Address([1u8; 32]);

        assert_eq!(monitor.consecutive_missed(&val), 0);
        assert_eq!(monitor.total_missed_count(&val), 0);
        assert!(!monitor.should_slash(&val));

        assert!(!monitor.record_miss(&val));
        assert_eq!(monitor.consecutive_missed(&val), 1);
        assert_eq!(monitor.total_missed_count(&val), 1);

        assert!(!monitor.record_miss(&val));
        assert_eq!(monitor.consecutive_missed(&val), 2);

        // Threshold reached at 3
        assert!(monitor.record_miss(&val));
        assert!(monitor.should_slash(&val));
        assert_eq!(monitor.consecutive_missed(&val), 3);
        assert_eq!(monitor.total_missed_count(&val), 3);

        // Success resets consecutive but preserves total
        monitor.record_success(&val);
        assert_eq!(monitor.consecutive_missed(&val), 0);
        assert_eq!(monitor.total_missed_count(&val), 3);
        assert!(!monitor.should_slash(&val));

        monitor.reset_validator(&val);
        assert_eq!(monitor.consecutive_missed(&val), 0);
    }
}
