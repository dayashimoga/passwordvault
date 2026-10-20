use proptest::prelude::*;
use pwdvault_generator::{
    calculate_entropy, estimate_crack_time, generate_passphrase, generate_password,
    wordlist::EFF_WORDLIST, Capitalization, PassphraseOptions, PasswordOptions,
};

const AMBIGUOUS: &[char] = &['1', 'l', 'I', '|', '0', 'O', 'Q', '8', 'B'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_password_length_and_classes(
        len in 8usize..=128usize,
        include_upper in any::<bool>(),
        include_lower in any::<bool>(),
        include_digits in any::<bool>(),
        include_symbols in any::<bool>(),
        exclude_ambiguous in any::<bool>(),
    ) {
        // Ensure at least one character set is selected
        let (upper, lower, digits, symbols) = if !include_upper && !include_lower && !include_digits && !include_symbols {
            (true, true, true, false)
        } else {
            (include_upper, include_lower, include_digits, include_symbols)
        };

        let opts = PasswordOptions {
            length: len,
            uppercase: upper,
            lowercase: lower,
            digits,
            symbols,
            exclude_ambiguous,
            custom_excluded: String::new(),
        };

        let pwd = generate_password(&opts).expect("Password generation should succeed");
        prop_assert_eq!(pwd.chars().count(), len);

        // Ambiguous exclusion check
        if exclude_ambiguous {
            for ch in pwd.chars() {
                prop_assert!(!AMBIGUOUS.contains(&ch), "Password contains ambiguous char: {}", ch);
            }
        }

        // Character class inclusion check
        if upper {
            prop_assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
        }
        if lower {
            prop_assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
        }
        if digits {
            prop_assert!(pwd.chars().any(|c| c.is_ascii_digit()));
        }
        if symbols {
            prop_assert!(pwd.chars().any(|c| !c.is_alphanumeric() && c.is_ascii_graphic()));
        }

        // Entropy and crack time sanity
        let ent = calculate_entropy(&pwd);
        prop_assert!(ent > 0.0);
        let crack = estimate_crack_time(&pwd);
        prop_assert!(crack.entropy_bits > 0);
        prop_assert!(!crack.online_time.is_empty());
        prop_assert!(!crack.offline_gpu_time.is_empty());
    }

    #[test]
    fn prop_passphrase_properties(
        word_count in 3usize..=10usize,
        separator in prop::sample::select(vec!["-", " ", ".", "_", "/"]),
        cap_idx in 0u8..3u8,
        insert_number in any::<bool>(),
    ) {
        let capitalization = match cap_idx {
            0 => Capitalization::Lowercase,
            1 => Capitalization::Uppercase,
            _ => Capitalization::TitleCase,
        };

        let opts = PassphraseOptions {
            word_count,
            separator: separator.to_string(),
            capitalization,
            insert_number,
        };

        let phrase = generate_passphrase(&opts).expect("Passphrase generation should succeed");
        let parts: Vec<&str> = phrase.split(separator).collect();
        let expected_count = if insert_number { word_count + 1 } else { word_count };
        prop_assert_eq!(parts.len(), expected_count);

        if insert_number {
            let last_part = parts.last().unwrap();
            prop_assert!(last_part.chars().all(|c| c.is_ascii_digit()), "Last part must be inserted digits");
        }

        // Check word parts
        for part in &parts[..word_count] {
            let lower = part.to_ascii_lowercase();
            prop_assert!(EFF_WORDLIST.contains(&lower.as_str()), "Word '{}' not in EFF list", part);

            match capitalization {
                Capitalization::Lowercase => {
                    prop_assert_eq!(*part, &part.to_ascii_lowercase());
                }
                Capitalization::Uppercase => {
                    prop_assert_eq!(*part, &part.to_ascii_uppercase());
                }
                Capitalization::TitleCase => {
                    if let Some(first) = part.chars().next() {
                        prop_assert!(first.is_ascii_uppercase());
                    }
                }
            }
        }
    }
}
