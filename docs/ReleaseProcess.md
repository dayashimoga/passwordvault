# Release Engineering & Security Assurance Process

## 1. Release Verification Pipeline
Before any build is labeled for release, the following gates must be met:
1. **Code & Linter Verification:**
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `flutter analyze`
2. **Automated Security Auditing:**
   - `cargo audit` (zero advisory warnings).
   - SBOM generation via `cargo cyclonedx` / `syft`.
   - Dependency license compliance check (compatible licenses: MIT, Apache-2.0, BSD-3-Clause).
3. **Multi-Tier Test Harness:**
   - 100% passing core unit, integration, and property tests.
   - Known-answer cryptographic test vectors verified.
   - Persistence tamper and truncation tests verified.
4. **Code Signing:**
   - Windows: Authenticode code signing with verified timestamping authority.
   - Android: APK Signature Scheme v3 / Google Play App Signing.
   - Apple: Apple Developer ID Application / Provisioning profile.

---

## 2. Release Artifact Integrity
- Every release artifact must be published with corresponding cryptographic checksums:
  - `SHA256SUMS.txt`
  - `BLAKE3SUMS.txt`
- Cryptographic signatures (`.sig` / Minisign / GPG) published alongside checksums.
