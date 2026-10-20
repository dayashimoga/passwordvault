# Security Risk Register & Residual Risk Disclosures

## 1. Risk Register

| Risk ID | Vulnerability / Threat Scenario | Inherent Severity | Mitigation Implemented | Residual Severity | Residual Risk / Operational Tradeoff |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RISK-01** | Kernel/Root-Level Host Malware on Unlocked Device | Critical | Memory zeroization, `VirtualLock`/`mlock`, auto-lock timeout. | High | If OS kernel is compromised, malware with ring 0 / admin rights can inspect memory or log raw keystrokes. Mitigated by prompt auto-lock, but host trust is a fundamental physical assumption. |
| **RISK-02** | User Forgets Both Master Passphrase & Recovery Key | Critical | Emergency Recovery Kit creation workflow, prominent warnings. | Medium | By cryptographic design, no backdoor exists. Data is permanently unrecoverable. Never auto-wipe to avoid malicious destruction. |
| **RISK-03** | System Clipboard Snooping by Accessibility Apps | High | Time-bounded auto-clear (30s), avoid overwrite of newer clips, preference for autofill. | Medium | Third-party clipboard history managers or accessibility services can capture copied text before 30-second clear. Clear warning banner shown in UI. |
| **RISK-04** | Hardware Cold-Boot / Sleep Memory Attack | High | Auto-lock on display sleep/lock; memory zeroization on lock. | Low | Seizure of unlocked device in RAM sleep state before timeout. Users in high-threat environments are advised to set timeout to 1 minute or manually lock. |
| **RISK-05** | Lookalike Domain Phishing (Punycode Attacks) | High | Strict eTLD+1 matching, punycode ASCII conversion, explicit user confirmation. | Low | User manually overrides warnings and forces autofill on malicious spoof domain. |
| **RISK-06** | Third-Party Rust Crate Supply Chain Tampering | High | Pinned `Cargo.lock`, `cargo audit`, zero unnecessary dependencies, verified licenses. | Low | Undetected zero-day vulnerability in vetted core cryptographic crates. |
| **RISK-07** | Partial Disk Write / Power Loss During Vault Save | High | Write-to-temp (`.tmp`), `fsync`/`FlushFileBuffers`, atomic rename commit. | Very Low | File system corruption at hardware controller level. Mitigated by automatic `.backup` retention. |
