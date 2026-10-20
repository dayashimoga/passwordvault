# Developer Guide & Engineering Conventions

## 1. Rust Code Quality & Safety Rules
- **No Unsafe Code Without Justification:** By default, `#![forbid(unsafe_code)]` or `#![deny(unsafe_code)]` is enforced on all pure crates (`crypto`, `vault`, `generator`, `search`, `backup`, `import_export`, `sync`).
- **FFI Unsafe Isolation:** Unavoidable `unsafe` code in `core/ffi` must be minimal, contained in dedicated wrapper functions, and accompanied by explicit `// SAFETY:` invariant comments.
- **Strict Linting:** All crates must pass `cargo clippy --workspace --all-targets -- -D warnings`.
- **Formatting:** Code must adhere strictly to `cargo fmt --all`.
- **Zeroize Invariant:** Any struct holding sensitive material must implement `Zeroize` and `ZeroizeOnDrop`. Never implement `Clone` or `Debug` that exposes plaintext credentials.

---

## 2. Testing Guidelines
- Every cryptographic operation must include known-answer test vectors (KATs) from RFCs.
- Every persistence format must include bit-flip tamper tests, truncated file tests, and wrong-password rejection tests.
- Performance critical paths (Argon2id, Search query, Decryption) must include Criterion benchmarks under `/benchmarks/`.

---

## 3. Flutter & UI Guidelines
- Avoid hardcoded colors or sizes; use the central theme tokens defined in `lib/presentation/theme/`.
- Ensure all interactive elements have semantic accessibility labels (`Semantics` widget).
- Support keyboard navigation (`FocusNode`, `Shortcuts`, `Actions`) across desktop platforms.
- Overwrite and clear text editing controllers holding sensitive secrets immediately after reading.
