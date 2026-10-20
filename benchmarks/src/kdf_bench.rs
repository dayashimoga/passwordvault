use pwdvault_crypto::{derive_kek, KdfParams};
use pwdvault_vault::{ItemCategory, VaultContainer, VaultItem, VaultPayload};
use std::time::Instant;

fn benchmark_kdf(profile_name: &str, params: &KdfParams, passphrase: &[u8]) {
    println!("--------------------------------------------------");
    println!("Benchmarking Profile: {}", profile_name);
    println!(
        "Memory: {} KiB ({} MiB), Iterations: {}, Parallelism: {}",
        params.memory_kib,
        params.memory_kib / 1024,
        params.iterations,
        params.parallelism
    );

    let start = Instant::now();
    let kek = derive_kek(passphrase, params).expect("KDF derivation failed");
    let elapsed = start.elapsed();

    println!("-> KDF Derivation Time: {:.2?}", elapsed);
    println!("-> KEK Derived: {:02x?} (32 bytes derived)", &kek[..4]);
}

fn benchmark_vault_cycle() {
    println!("==================================================");
    println!("Benchmarking Vault Creation & Unlock Cycle");
    let kdf = KdfParams::test_profile().expect("Valid test params");
    let passphrase = b"benchmarking-strong-passphrase-2026";

    let mut payload = VaultPayload::new("Benchmark Vault");
    for i in 0..100 {
        payload.items.push(VaultItem {
            id: format!("uuid-{}", i),
            title: format!("Service {}", i),
            category: ItemCategory::Login,
            username: Some(format!("user_{}@example.com", i)),
            password: Some(format!("password-secret-{}", i)),
            urls: vec![format!("https://service{}.example.com", i)],
            notes: Some("Encrypted benchmark item".into()),
            totp_seed: None,
            tags: vec!["benchmark".into()],
            favorite: i % 5 == 0,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        });
    }

    // 1. Vault Creation
    let start_create = Instant::now();
    let raw_vault = VaultContainer::create(passphrase, kdf.clone(), &payload)
        .expect("VaultContainer::create failed");
    let create_elapsed = start_create.elapsed();
    println!(
        "-> Encrypted Vault Size: {} bytes (100 items)",
        raw_vault.len()
    );
    println!("-> Creation + Encryption Elapsed: {:.2?}", create_elapsed);

    // 2. Vault Unlock
    let start_unlock = Instant::now();
    let (header, _dek, unlocked_payload) =
        VaultContainer::unlock(&raw_vault, passphrase).expect("VaultContainer::unlock failed");
    let unlock_elapsed = start_unlock.elapsed();
    println!("-> Unlock + Decryption Elapsed: {:.2?}", unlock_elapsed);
    println!(
        "-> Verified Unlocked Items: {}",
        unlocked_payload.items.len()
    );
    println!("-> Header Version: {}", header.version);
    println!("==================================================");
}

fn main() {
    println!("=== PWDVAULT CRYPTOGRAPHIC BENCHMARK HARNESS ===");
    let passphrase = b"correct-horse-battery-staple-sample-passphrase";

    // 1. Test profile (16 MiB)
    let test_p = KdfParams::test_profile().unwrap();
    benchmark_kdf("Fast Test Profile", &test_p, passphrase);

    // 2. Mobile profile (64 MiB)
    let mobile_p = KdfParams::mobile_default().unwrap();
    benchmark_kdf("Mobile Baseline Profile", &mobile_p, passphrase);

    // 3. Desktop profile (128 MiB)
    let desktop_p = KdfParams::desktop_default().unwrap();
    benchmark_kdf("Desktop Baseline Profile", &desktop_p, passphrase);

    // 4. Vault creation and unlock
    benchmark_vault_cycle();
}
