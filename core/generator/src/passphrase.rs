use crate::error::GeneratorError;
use crate::random::random_index;
use crate::wordlist::{get_word, wordlist_len};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Capitalization styling for passphrase words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capitalization {
    /// Keep all words in lowercase (e.g. `correct-horse-battery-staple`).
    Lowercase,
    /// Capitalize the first letter of each word (e.g. `Correct-Horse-Battery-Staple`).
    TitleCase,
    /// Uppercase every word (e.g. `CORRECT-HORSE-BATTERY-STAPLE`).
    Uppercase,
}

/// Configuration options for EFF-based passphrase generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseOptions {
    /// Number of words to select (between 3 and 10 words).
    pub word_count: usize,
    /// Separator between words (e.g. "-", " ", ".", "_").
    pub separator: String,
    /// Word capitalization styling.
    pub capitalization: Capitalization,
    /// Append or insert a random 2-digit number (10..99) for additional entropy.
    pub insert_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 5,
            separator: "-".to_string(),
            capitalization: Capitalization::TitleCase,
            insert_number: false,
        }
    }
}

impl PassphraseOptions {
    /// Validates passphrase configuration.
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if self.word_count < 3 || self.word_count > 10 {
            return Err(GeneratorError::InvalidConfig(
                "Passphrase word count must be between 3 and 10 words",
            ));
        }
        Ok(())
    }
}

/// Generates a high-entropy passphrase from the EFF wordlist according to options.
pub fn generate_passphrase(
    options: &PassphraseOptions,
) -> Result<Zeroizing<String>, GeneratorError> {
    options.validate()?;

    let total_words = wordlist_len();
    if total_words == 0 {
        return Err(GeneratorError::InvalidConfig("Wordlist is empty"));
    }

    let mut words: Vec<String> = Vec::with_capacity(options.word_count);

    for _ in 0..options.word_count {
        let idx = random_index(total_words)?;
        let word = get_word(idx).ok_or(GeneratorError::InvalidConfig(
            "Wordlist index out of bounds",
        ))?;

        let styled_word = match options.capitalization {
            Capitalization::Lowercase => word.to_lowercase(),
            Capitalization::Uppercase => word.to_uppercase(),
            Capitalization::TitleCase => {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            }
        };

        words.push(styled_word);
    }

    let mut result = words.join(&options.separator);

    if options.insert_number {
        let num = 10 + (random_index(90)?);
        result.push_str(&options.separator);
        result.push_str(&num.to_string());
    }

    Ok(Zeroizing::new(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passphrase_bounds() {
        let opts = PassphraseOptions {
            word_count: 2,
            ..Default::default()
        };
        assert!(generate_passphrase(&opts).is_err());

        let opts = PassphraseOptions {
            word_count: 11,
            ..Default::default()
        };
        assert!(generate_passphrase(&opts).is_err());

        let opts = PassphraseOptions {
            word_count: 4,
            ..Default::default()
        };
        let pass = generate_passphrase(&opts).unwrap();
        let parts: Vec<&str> = pass.split('-').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_passphrase_capitalization() {
        let opts = PassphraseOptions {
            word_count: 3,
            capitalization: Capitalization::Uppercase,
            separator: ".".into(),
            ..Default::default()
        };

        let pass = generate_passphrase(&opts).unwrap();
        for word in pass.split('.') {
            assert!(word.chars().all(|c| c.is_ascii_uppercase()));
        }
    }
}
