# Disaster Recovery & Cryptographic Emergency Kit Guide

## 1. Cryptographic Recovery Philosophy
- **Zero Backdoors:** There are no master keys, escrow accounts, developer recovery services, or security questions.
- **Explicit Cryptographic Recovery:** Vault recovery is performed strictly via the user's **Emergency Recovery Key** (a 256-bit cryptographically derived key formatted as a 24-word BIP-39 mnemonic or Base32 secret string).
- **Permanent Loss Disclosure:** If both the Master Passphrase and the Emergency Recovery Key are lost, the vault contents are mathematically unrecoverable. Failed attempts do not automatically wipe the vault (to prevent destructive attacks by malicious actors or curious family members), but offline guessing remains computationally infeasible due to Argon2id memory hardness.

---

## 2. Emergency Recovery Kit Generation
When a user creates a new vault:
1. A random 256-bit Recovery Key is generated from the OS CSPRNG.
2. The Vault Data Encryption Key (DEK) is encrypted with the Recovery Key and stored in the `RecoveryKeyEnvelope` in the vault header.
3. The Emergency Recovery Kit displays the recovery key formatted as:
   - 24 BIP-39 words with checksum.
   - High-contrast printable document layout.
   - Clear instructions on safe physical storage (e.g., safe deposit box, fireproof home safe).

---

## 3. Vault Restoration Procedure
1. Open the application on any supported device (Windows, Android, iOS, macOS, Linux).
2. Click **Restore from Backup / Emergency Key**.
3. Select your `.vault.v1` or `.vaultbak` file.
4. Select **Use Emergency Recovery Key**.
5. Enter the 24 recovery words.
6. Upon validation, the DEK is unwrapped, the vault is opened, and the user is immediately prompted to configure a new Master Passphrase.
