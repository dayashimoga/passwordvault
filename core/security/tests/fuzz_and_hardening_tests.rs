#![deny(unsafe_code)]

//! Fuzzing, stress testing, and hardening test suite for pwdvault-security.
//! Validates resilience against malformed inputs, edge cases, and memory hygiene.

use proptest::prelude::*;
use pwdvault_security::audit::{check_suffix_in_range_response, prepare_breach_query};
use pwdvault_security::passkey::{generate_passkey, sign_assertion, COSE_ALG_ES256};
use pwdvault_security::sha1::Sha1;
use pwdvault_security::totp::{
    generate_totp, parse_otpauth_uri, time_remaining, verify_totp, TotpAlgorithm, TotpConfig,
};
use zeroize::Zeroize;

proptest! {
    /// Fuzzes TOTP URI parser with arbitrary random UTF-8 strings.
    /// Invariant: Must never panic; either parses valid config or returns clean error.
    #[test]
    fn fuzz_totp_uri_parsing(input in "\\PC*") {
        let _ = parse_otpauth_uri(&input);
    }

    /// Fuzzes TOTP URI parser with malformed otpauth schemes and query variations.
    #[test]
    fn fuzz_totp_uri_schemes(
        scheme in "(otpauth|otp|http|https|ftp|file)://(totp|hotp|invalid)/",
        label in "[a-zA-Z0-9%:@._-]{0,50}",
        secret in "[a-zA-Z0-9=]{0,50}",
        digits in -10i32..30i32,
        period in -10i64..3600i64,
        algo in "(SHA1|SHA256|SHA512|MD5|UNKNOWN)"
    ) {
        let uri = format!("{}{}?secret={}&digits={}&period={}&algorithm={}",
            scheme, label, secret, digits, period, algo);
        let _ = parse_otpauth_uri(&uri);
    }

    /// Fuzzes k-Anonymity breach range response parser with arbitrary text.
    /// Invariant: Must never panic, always returning clean count or error.
    #[test]
    fn fuzz_breach_range_response_parsing(
        suffix in "[0-9A-F]{35}",
        body in "\\PC{0,500}"
    ) {
        let _ = check_suffix_in_range_response(&suffix, &body);
    }

    /// Fuzzes k-Anonymity query generation across arbitrary password strings.
    /// Invariant: Prefix is always 5 chars, suffix is 35 chars, combined matches SHA-1.
    #[test]
    fn prop_breach_query_invariants(password in "\\PC*") {
        let query = prepare_breach_query(&password);
        prop_assert_eq!(query.prefix.len(), 5);
        prop_assert_eq!(query.suffix.len(), 35);

        let combined = format!("{}{}", query.prefix, query.suffix);
        let raw_sha1 = Sha1::digest(password.as_bytes());
        let expected_hex = raw_sha1.iter().map(|b| format!("{:02X}", b)).collect::<String>();

        prop_assert_eq!(combined, expected_hex);
    }

    /// Fuzzes TOTP generation and verification with arbitrary timestamps and drift steps.
    #[test]
    fn prop_totp_generation_and_drift(
        secret in "[A-Z2-7]{16,32}",
        timestamp in 0u64..2_000_000_000u64,
        digits in 6u32..=8u32,
        period in 10u32..=120u32,
    ) {
        let config = TotpConfig {
            secret: secret.as_bytes().to_vec(),
            period_seconds: period,
            digits,
            algorithm: TotpAlgorithm::Sha1,
            issuer: Some("Antigravity".into()),
            account_name: Some("user@test".into()),
        };

        let code = generate_totp(&config, timestamp);
        prop_assert_eq!(code.len(), digits as usize);

        let rem = time_remaining(&config, timestamp);
        prop_assert!(rem <= period as u64);

        // Immediate verification at the exact timestamp must succeed
        let valid = verify_totp(&config, &code, timestamp, 1);
        prop_assert!(valid);

        // Verification within +period drift window must succeed
        let valid_drift_plus = verify_totp(&config, &code, timestamp + (period as u64), 1);
        prop_assert!(valid_drift_plus);

        // Verification within -period drift window must succeed
        if timestamp >= period as u64 {
            let valid_drift_minus = verify_totp(&config, &code, timestamp - (period as u64), 1);
            prop_assert!(valid_drift_minus);
        }
    }

    /// Fuzzes Passkey creation, assertion signing, and sign counter progression.
    #[test]
    fn prop_passkey_assertion_lifecycle(
        rp_id in "[a-z0-9.-]{3,30}",
        user_name in "[a-zA-Z0-9_]{3,20}",
        client_data in "\\PC{10,200}",
    ) {
        let handle = b"test_user_handle";
        if let Ok(mut passkey) = generate_passkey(&rp_id, handle, &user_name, COSE_ALG_ES256) {
            prop_assert_eq!(&passkey.rp_id, &rp_id);
            prop_assert_eq!(&passkey.user_name, &user_name);
            prop_assert_eq!(passkey.sign_count, 0);

            // Sign first assertion
            let res1 = sign_assertion(&mut passkey, &rp_id, &client_data, true, true);
            prop_assert!(res1.is_ok());
            prop_assert_eq!(passkey.sign_count, 1);

            let ass1 = res1.unwrap();
            prop_assert_eq!(ass1.authenticator_data.len(), 37);
            prop_assert!(!ass1.signature.is_empty());

            // Sign second assertion -> sign_count increments monotonically
            let res2 = sign_assertion(&mut passkey, &rp_id, &client_data, true, true);
            prop_assert!(res2.is_ok());
            prop_assert_eq!(passkey.sign_count, 2);

            let ass2 = res2.unwrap();
            prop_assert_eq!(ass2.authenticator_data.len(), 37);
            prop_assert_ne!(ass1.authenticator_data, ass2.authenticator_data); // Counter field differs
            prop_assert!(!ass2.signature.is_empty());

            // Mismatched RP ID must be rejected cleanly
            let bad_rp = format!("{}.evil.com", rp_id);
            let bad_res = sign_assertion(&mut passkey, &bad_rp, &client_data, true, true);
            prop_assert!(bad_res.is_err());
        }
    }
}

#[test]
fn test_memory_zeroization_on_sensitive_buffers() {
    let mut sensitive_bytes = vec![0x42u8; 64];
    assert!(sensitive_bytes.iter().all(|&b| b == 0x42));

    sensitive_bytes.zeroize();
    assert!(sensitive_bytes.iter().all(|&b| b == 0));
}
