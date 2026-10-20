use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Entry in the ephemeral password generation history.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GenerationHistoryEntry {
    /// Generated plaintext secret.
    pub secret: String,
    /// Unix timestamp of generation.
    #[zeroize(skip)]
    pub timestamp: u64,
    /// Calculated entropy bits.
    #[zeroize(skip)]
    pub entropy_bits: u32,
}

/// Ephemeral in-memory ring buffer holding recently generated passwords.
///
/// Guaranteed to be zeroized on drop or explicit clearance. Never written to disk.
#[derive(Debug, Default)]
pub struct EphemeralGenerationHistory {
    max_entries: usize,
    entries: VecDeque<GenerationHistoryEntry>,
}

impl EphemeralGenerationHistory {
    /// Creates a new ephemeral history buffer with bounded capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.clamp(5, 50),
            entries: VecDeque::with_capacity(max_entries),
        }
    }

    /// Appends a new generated secret to the history, evicting the oldest entry if full.
    pub fn record(&mut self, secret: String, entropy_bits: u32, timestamp: u64) {
        if self.entries.len() >= self.max_entries {
            if let Some(mut old) = self.entries.pop_front() {
                old.zeroize();
            }
        }

        self.entries.push_back(GenerationHistoryEntry {
            secret,
            timestamp,
            entropy_bits,
        });
    }

    /// Returns the list of active entries.
    pub fn entries(&self) -> &VecDeque<GenerationHistoryEntry> {
        &self.entries
    }

    /// Clears and immediately zeroizes all entries.
    pub fn clear(&mut self) {
        for mut entry in self.entries.drain(..) {
            entry.zeroize();
        }
    }
}

impl Zeroize for EphemeralGenerationHistory {
    fn zeroize(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.zeroize();
        }
        self.entries.clear();
    }
}

impl Drop for EphemeralGenerationHistory {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_history_bounding() {
        let mut history = EphemeralGenerationHistory::new(5);
        for i in 0..10 {
            history.record(format!("secret-{}", i), 60, 1000 + i);
        }

        assert_eq!(history.entries().len(), 5);
        assert_eq!(history.entries()[0].secret, "secret-5");
        assert_eq!(history.entries()[4].secret, "secret-9");

        history.clear();
        assert_eq!(history.entries().len(), 0);
    }
}
