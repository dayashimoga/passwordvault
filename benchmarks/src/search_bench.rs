use pwdvault_search::{SearchIndex, SearchQuery};
use pwdvault_vault::{ItemCategory, VaultItem, VaultPayload};
use std::time::Instant;

fn generate_synthetic_items(count: usize) -> Vec<VaultItem> {
    let services = [
        "GitHub",
        "Google Workspace",
        "AWS Console",
        "ProtonMail",
        "Slack",
        "Bank of America",
        "Stripe Dashboard",
        "Docker Hub",
        "GitLab Enterprise",
        "DigitalOcean",
        "Cloudflare",
        "Figma Design",
        "Notion Workspace",
        "Jira Software",
        "Bitwarden Migration",
        "Discord",
        "Apple ID",
        "Microsoft 365",
        "Twitter / X",
        "LinkedIn Recruiter",
    ];

    let tags = [
        "work", "personal", "finance", "devops", "cloud", "security", "infra",
    ];

    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let base_service = services[i % services.len()];
        let item_title = format!("{} Item #{}", base_service, i);
        let username = format!(
            "user_{}_{}@company.example.com",
            i % 500,
            base_service.to_lowercase().replace(' ', "")
        );
        let url = format!(
            "https://{}.example.com/login?id={}",
            base_service.to_lowercase().replace(' ', ""),
            i
        );
        let tag = tags[i % tags.len()].to_string();

        items.push(VaultItem {
            id: format!("uuid-item-{:08}", i),
            title: item_title,
            category: match i % 5 {
                0 => ItemCategory::Login,
                1 => ItemCategory::SecureNote,
                2 => ItemCategory::PaymentCard,
                3 => ItemCategory::Identity,
                _ => ItemCategory::RecoveryCode,
            },
            username: Some(username),
            password: Some("super-secret-vault-password".into()),
            urls: vec![url],
            notes: Some("Confidential notes stored in vault".into()),
            totp_seed: None,
            tags: vec![tag, "production".into()],
            favorite: i % 10 == 0,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: 1700000000 + i as u64,
            updated_at: 1700000000 + i as u64,
        });
    }

    items
}

fn benchmark_search_scale(item_count: usize) {
    println!("==================================================");
    println!("Benchmarking Search Index with {} items", item_count);

    let items = generate_synthetic_items(item_count);
    let mut payload = VaultPayload::new(format!("Scale {} Vault", item_count));
    payload.items = items;

    // 1. Measure index build time
    let start_build = Instant::now();
    let index = SearchIndex::from_payload(&payload);
    let build_elapsed = start_build.elapsed();
    println!("-> Index Build Elapsed: {:.2?}", build_elapsed);

    // 2. Prepare query suite
    let query_strings = [
        "github",
        "google",
        "aws console",
        "proton",
        "slack",
        "bank",
        "githbu", // typo / fuzzy trigram
        "amzon",  // typo / fuzzy trigram
        "digital",
        "user_42",
        "company.example.com",
        "devops",
        "nonexistentterm999",
    ];

    let iterations = 1000;
    let mut latencies_micros = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let q_str = query_strings[i % query_strings.len()];
        let query = if i % 4 == 0 {
            SearchQuery::new(q_str).with_category(ItemCategory::Login)
        } else if i % 4 == 1 {
            SearchQuery::new(q_str).with_tag("production")
        } else {
            SearchQuery::new(q_str)
        };

        let start_q = Instant::now();
        let results = index.search(&query);
        let elapsed_micros = start_q.elapsed().as_micros() as u64;
        latencies_micros.push(elapsed_micros);

        if i == 0 {
            println!(
                "   [Sanity check] query '{}' returned {} results",
                q_str,
                results.len()
            );
        }
    }

    latencies_micros.sort_unstable();

    let p50 = latencies_micros[latencies_micros.len() * 50 / 100];
    let p95 = latencies_micros[latencies_micros.len() * 95 / 100];
    let p99 = latencies_micros[latencies_micros.len() * 99 / 100];
    let max = latencies_micros[latencies_micros.len() - 1];
    let avg = latencies_micros.iter().sum::<u64>() as f64 / latencies_micros.len() as f64;

    println!("-> Latency Stats (over {} query iterations):", iterations);
    println!("   Avg: {:.2} µs ({:.3} ms)", avg, avg / 1000.0);
    println!("   p50: {} µs ({:.3} ms)", p50, p50 as f64 / 1000.0);
    println!("   p95: {} µs ({:.3} ms)", p95, p95 as f64 / 1000.0);
    println!("   p99: {} µs ({:.3} ms)", p99, p99 as f64 / 1000.0);
    println!("   Max: {} µs ({:.3} ms)", max, max as f64 / 1000.0);

    let p95_ms = p95 as f64 / 1000.0;
    assert!(
        p95_ms < 50.0,
        "VIOLATION: Search p95 latency ({:.2}ms) exceeded 50ms requirement!",
        p95_ms
    );
    println!(
        "-> Requirement verified: p95 < 50ms (actual: {:.3}ms) [PASSED]",
        p95_ms
    );
    println!("==================================================");
}

fn main() {
    println!("=== PWDVAULT SEARCH INDEX BENCHMARK HARNESS ===");
    // Scale 1: 10,000 items (standard power user)
    benchmark_search_scale(10_000);

    // Scale 2: 100,000 items (enterprise stress test)
    benchmark_search_scale(100_000);
}
