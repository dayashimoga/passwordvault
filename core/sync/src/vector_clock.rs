#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Monotonic Vector Clock implementation for distributed multi-device causality tracking.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Monotonic vector clock tracking Lamport sequence numbers per device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VectorClock {
    /// Mapping of device identifier to its highest monotonically increasing sequence number.
    pub clocks: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Creates a new empty vector clock.
    pub fn new() -> Self {
        Self {
            clocks: BTreeMap::new(),
        }
    }

    /// Increments the clock for a specific device, advancing its logical timeline.
    pub fn increment(&mut self, device_id: &str) -> u64 {
        let entry = self.clocks.entry(device_id.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Retrieves the sequence counter for a specific device.
    pub fn get(&self, device_id: &str) -> u64 {
        self.clocks.get(device_id).copied().unwrap_or(0)
    }

    /// Merges another vector clock by taking the component-wise maximum of all sequence counters.
    pub fn merge(&mut self, other: &VectorClock) {
        for (device, &counter) in &other.clocks {
            let entry = self.clocks.entry(device.clone()).or_insert(0);
            if counter > *entry {
                *entry = counter;
            }
        }
    }

    /// Returns `true` if `self` strictly dominates or equals `other` across all components.
    pub fn dominates(&self, other: &VectorClock) -> bool {
        for (device, &other_counter) in &other.clocks {
            if self.get(device) < other_counter {
                return false;
            }
        }
        true
    }

    /// Returns `true` if `self` and `other` are causally concurrent (neither dominates the other).
    pub fn is_concurrent(&self, other: &VectorClock) -> bool {
        !self.dominates(other) && !other.dominates(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_monotonic_progression() {
        let mut clock = VectorClock::new();
        assert_eq!(clock.get("dev1"), 0);

        assert_eq!(clock.increment("dev1"), 1);
        assert_eq!(clock.increment("dev1"), 2);
        assert_eq!(clock.get("dev1"), 2);
    }

    #[test]
    fn test_vector_clock_causality_and_concurrency() {
        let mut clock_a = VectorClock::new();
        clock_a.increment("dev_a"); // dev_a: 1

        let mut clock_b = VectorClock::new();
        clock_b.increment("dev_b"); // dev_b: 1

        // Concurrent: A has dev_a:1, B has dev_b:1
        assert!(clock_a.is_concurrent(&clock_b));
        assert!(clock_b.is_concurrent(&clock_a));
        assert!(!clock_a.dominates(&clock_b));

        // Merge B into A
        clock_a.merge(&clock_b); // dev_a: 1, dev_b: 1
        assert!(clock_a.dominates(&clock_b));
        assert!(!clock_b.dominates(&clock_a));
        assert!(!clock_a.is_concurrent(&clock_b));
    }
}
