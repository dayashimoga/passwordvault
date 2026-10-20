use crate::error::GeneratorError;
use crate::random::{random_index, shuffle};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &str = "0123456789";
const SYMBOL_CHARS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";
const AMBIGUOUS_CHARS: &str = "1lI|0OQ8B";

/// Configuration options for random password generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordOptions {
    /// Password length (between 8 and 128 characters).
    pub length: usize,
    /// Include uppercase ASCII letters [A-Z].
    pub uppercase: bool,
    /// Include lowercase ASCII letters [a-z].
    pub lowercase: bool,
    /// Include numeric digits [0-9].
    pub digits: bool,
    /// Include punctuation and symbols.
    pub symbols: bool,
    /// Exclude visually ambiguous characters (e.g. 1, l, I, 0, O, 8, B).
    pub exclude_ambiguous: bool,
    /// User-defined characters to explicitly exclude.
    pub custom_excluded: String,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            custom_excluded: String::new(),
        }
    }
}

impl PasswordOptions {
    /// Validates options constraints.
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if self.length < 8 || self.length > 128 {
            return Err(GeneratorError::InvalidConfig(
                "Password length must be between 8 and 128 characters",
            ));
        }

        if !self.uppercase && !self.lowercase && !self.digits && !self.symbols {
            return Err(GeneratorError::InvalidConfig(
                "At least one character class must be selected",
            ));
        }

        Ok(())
    }
}

/// Generates a cryptographically secure, unbiased random password according to the options.
///
/// Ensures:
/// 1. Unbiased character selection via rejection sampling.
/// 2. At least one character from each enabled class is included.
/// 3. Character positions are randomized via Fisher-Yates shuffle.
/// 4. Result is wrapped in a `Zeroizing<String>` to sanitize memory on drop.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>, GeneratorError> {
    options.validate()?;

    let filter_pool = |raw: &str| -> Vec<char> {
        raw.chars()
            .filter(|&c| {
                if options.exclude_ambiguous && AMBIGUOUS_CHARS.contains(c) {
                    return false;
                }
                if options.custom_excluded.contains(c) {
                    return false;
                }
                true
            })
            .collect()
    };

    let mut enabled_pools: Vec<Vec<char>> = Vec::new();
    let mut combined_pool: Vec<char> = Vec::new();

    if options.uppercase {
        let p = filter_pool(UPPERCASE_CHARS);
        if !p.is_empty() {
            combined_pool.extend_from_slice(&p);
            enabled_pools.push(p);
        }
    }
    if options.lowercase {
        let p = filter_pool(LOWERCASE_CHARS);
        if !p.is_empty() {
            combined_pool.extend_from_slice(&p);
            enabled_pools.push(p);
        }
    }
    if options.digits {
        let p = filter_pool(DIGIT_CHARS);
        if !p.is_empty() {
            combined_pool.extend_from_slice(&p);
            enabled_pools.push(p);
        }
    }
    if options.symbols {
        let p = filter_pool(SYMBOL_CHARS);
        if !p.is_empty() {
            combined_pool.extend_from_slice(&p);
            enabled_pools.push(p);
        }
    }

    if combined_pool.is_empty() {
        return Err(GeneratorError::InvalidConfig(
            "Character exclusions eliminated all available characters in chosen classes",
        ));
    }

    let mut result_chars: Vec<char> = Vec::with_capacity(options.length);

    // 1. Mandatory requirement: Ensure at least one character from each enabled category
    for pool in &enabled_pools {
        if result_chars.len() < options.length {
            let idx = random_index(pool.len())?;
            result_chars.push(pool[idx]);
        }
    }

    // 2. Fill the remaining length from the combined pool
    while result_chars.len() < options.length {
        let idx = random_index(combined_pool.len())?;
        result_chars.push(combined_pool[idx]);
    }

    // 3. Shuffle to avoid predictable class placement at initial indices
    shuffle(&mut result_chars)?;

    let password_str: String = result_chars.into_iter().collect();
    Ok(Zeroizing::new(password_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_length_bounds() {
        let opts = PasswordOptions {
            length: 7,
            ..Default::default()
        };
        assert!(generate_password(&opts).is_err());

        let opts = PasswordOptions {
            length: 129,
            ..Default::default()
        };
        assert!(generate_password(&opts).is_err());

        let opts = PasswordOptions {
            length: 16,
            ..Default::default()
        };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_class_enforcement() {
        let opts = PasswordOptions {
            length: 12,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            custom_excluded: String::new(),
        };

        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOL_CHARS.contains(c)));
        }
    }

    #[test]
    fn test_ambiguous_character_exclusion() {
        let opts = PasswordOptions {
            length: 32,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
            custom_excluded: String::new(),
        };

        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            for amb in AMBIGUOUS_CHARS.chars() {
                assert!(
                    !pw.contains(amb),
                    "Password contained ambiguous char: {}",
                    amb
                );
            }
        }
    }
}
