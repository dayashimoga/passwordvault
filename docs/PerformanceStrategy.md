# Performance Strategy & Benchmark Metrics

## 1. Concrete Performance Targets

| Target Metric | Baseline Threshold | Strict Ceiling | Measurement Method |
| :--- | :--- | :--- | :--- |
| **Cold Startup Time** | < 1.0s | < 2.0s | Launch binary to interactive locked UI screen (excluding Argon2id compute). |
| **Search Query Latency (10k items)** | p95 < 15ms | p95 < 50ms | In-memory trigram index query benchmark with Criterion. |
| **Search Query Latency (100k items)**| p95 < 35ms | p95 < 80ms | In-memory trigram index query benchmark with Criterion. |
| **Steady-State App Memory** | < 100 MB | < 150 MB (Desktop) / < 250 MB (Mobile peak) | OS process memory monitor (`GetProcessMemoryInfo` / `/proc/self/status`). |
| **Idle CPU Utilization** | < 0.2% | < 1.0% | Averaged over 60-second window when vault is locked or idle. |
| **UI Frame Rendering** | 120 / 60 FPS | 0 dropped frames | Flutter DevTools Frame Timing / Android Frame Metrics API. |

---

## 2. Resource Management & Optimization Tactics
1. **Zero-Copy In-Memory Records:** During search, only lightweight references (`ItemId`, title, match score) are returned to the UI thread. Full item details are only materialized when the user clicks an item.
2. **KDF Parallelism Bounding:** Argon2id threads are clamped to `min(p_cost, num_cpus)` to avoid thread contention on lower-end mobile devices.
3. **No Continuous Background Polling:** Auto-lock uses OS timer events rather than an active polling loop. Network sync (Phase 6) operates strictly event-driven or on user trigger.
