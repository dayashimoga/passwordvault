use serde::{Deserialize, Serialize};

/// Qualitative strength rating based on calculated entropy bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StrengthRating {
    /// Less than 30 bits: trivial to break in seconds.
    VeryWeak,
    /// 30 to 45 bits: vulnerable to modest offline dictionary attack.
    Weak,
    /// 45 to 60 bits: resistant to online guessing, vulnerable to fast GPU cracking.
    Fair,
    /// 60 to 85 bits: high security, computationally infeasible to brute force.
    Strong,
    /// 85+ bits: military-grade entropy, resistant to nation-state clusters.
    VeryStrong,
}

/// Realistic crack-time estimates based on different attacker hardware models.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrackTimeEstimate {
    /// Entropy in bits.
    pub entropy_bits: u32,
    /// Strength classification rating.
    pub rating: StrengthRating,
    /// Time to crack at 100 attempts/sec (online rate-limited service).
    pub online_time: String,
    /// Time to crack at 100 GH/s (consumer/enthusiast multi-GPU rig).
    pub offline_gpu_time: String,
    /// Time to crack at 10 TH/s (distributed ASIC/nation-state cluster).
    pub cluster_time: String,
}

/// Computes Shannon / pool-based entropy in bits for a given password string.
pub fn calculate_entropy(secret: &str) -> f64 {
    if secret.is_empty() {
        return 0.0;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_space = false;

    for ch in secret.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch == ' ' {
            has_space = true;
        } else {
            has_symbol = true;
        }
    }

    let mut pool_size: f64 = 0.0;
    if has_lower {
        pool_size += 26.0;
    }
    if has_upper {
        pool_size += 26.0;
    }
    if has_digit {
        pool_size += 10.0;
    }
    if has_symbol {
        pool_size += 33.0;
    }
    if has_space {
        pool_size += 1.0;
    }

    if pool_size <= 1.0 {
        return 0.0;
    }

    let len = secret.chars().count() as f64;
    let base_entropy = len * pool_size.log2();

    // Deduct penalties for consecutive repeated characters
    let mut penalty = 0.0;
    let mut prev_char = None;
    let mut repeat_streak = 0;

    for ch in secret.chars() {
        if Some(ch) == prev_char {
            repeat_streak += 1;
            penalty += (repeat_streak as f64) * 1.5;
        } else {
            repeat_streak = 0;
            prev_char = Some(ch);
        }
    }

    (base_entropy - penalty).max(0.0)
}

/// Formats seconds into human-readable duration strings.
fn format_seconds(seconds: f64) -> String {
    if seconds < 1.0 {
        "Instant".to_string()
    } else if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 31_536_000.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else if seconds < 3_153_600_000.0 {
        format!("{:.0} years", seconds / 31_536_000.0)
    } else if seconds < 315_360_000_000.0 {
        format!("{:.0} centuries", seconds / 3_153_600_000.0)
    } else {
        "Centuries+".to_string()
    }
}

/// Evaluates crack-time models and strength ratings.
pub fn estimate_crack_time(secret: &str) -> CrackTimeEstimate {
    let entropy = calculate_entropy(secret);
    let entropy_rounded = entropy.round() as u32;

    let rating = if entropy < 30.0 {
        StrengthRating::VeryWeak
    } else if entropy < 45.0 {
        StrengthRating::Weak
    } else if entropy < 60.0 {
        StrengthRating::Fair
    } else if entropy < 85.0 {
        StrengthRating::Strong
    } else {
        StrengthRating::VeryStrong
    };

    // Total combinations = 2^entropy
    let combinations = 2.0_f64.powf(entropy);
    // Average attempts to crack = combinations / 2
    let avg_attempts = combinations / 2.0;

    let online_rate = 100.0; // 100 guesses / sec
    let offline_gpu_rate = 100_000_000_000.0; // 100 GH/s
    let cluster_rate = 10_000_000_000_000.0; // 10 TH/s

    CrackTimeEstimate {
        entropy_bits: entropy_rounded,
        rating,
        online_time: format_seconds(avg_attempts / online_rate),
        offline_gpu_time: format_seconds(avg_attempts / offline_gpu_rate),
        cluster_time: format_seconds(avg_attempts / cluster_rate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_ratings() {
        assert_eq!(
            estimate_crack_time("123456").rating,
            StrengthRating::VeryWeak
        );
        assert_eq!(estimate_crack_time("abcdefgh").rating, StrengthRating::Weak);
        assert_eq!(
            estimate_crack_time("password123").rating,
            StrengthRating::Fair
        );
        assert_eq!(
            estimate_crack_time("hunter2pass1234").rating,
            StrengthRating::Strong
        );
        assert_eq!(
            estimate_crack_time("correct-horse-battery-staple").rating,
            StrengthRating::VeryStrong
        );
        assert_eq!(
            estimate_crack_time("K9#m$L2!zQ&vW8*pY4@xN1%b").rating,
            StrengthRating::VeryStrong
        );
    }
}
