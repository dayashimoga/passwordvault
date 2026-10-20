# ADR-003: FFI Boundary and Flutter UI Integration

## Status
**Decided / Accepted**

## Date
2026-10-19

## Context
The application combines a high-assurance, memory-safe Rust core with a cross-platform, responsive Flutter UI for Desktop (Windows, macOS, Linux) and Mobile/Tablet (Android, iOS). We need a clear architectural boundary that minimizes unsafe code, prevents memory leaks, enforces strict typing, and isolates managed runtime garbage collection from unmanaged native memory.

## Decision
We establish a **minimal typed C-ABI and Flutter Rust Bridge boundary** under `/core/ffi`.

### Architectural Rules
1. **No Business Logic in Dart:** Dart/Flutter code is strictly responsible for presentation, layout, accessibility, and platform UI events. 100% of cryptography, validation, search, persistence, and state management belongs to Rust.
2. **Zero Plaintext Leaks in Bridge:**
   - Raw master passphrases passed from Dart to Rust across FFI are consumed immediately by Rust worker threads into zeroizable byte arrays (`Zeroizing<Vec<u8>>`).
   - Dart string garbage collection cannot guarantee immediate zeroization; therefore, UI controllers must nullify and overwrite password text controller buffers as soon as FFI invocation completes.
3. **Structured Result Passing:**
   - All FFI functions return a standardized `VaultFfiResult<T>` struct containing an explicit integer error code, an optional error message, and the return payload.
   - Rust panics are caught at the FFI boundary using `std::panic::catch_unwind` and translated to explicit error results. No panic is permitted to unwind across the FFI C-ABI boundary (which would cause undefined behavior).
4. **Asynchronous Execution:**
   - Heavy Rust calls (vault unlock, KDF derivation, bulk search, import parsing, backups) are invoked asynchronously via Dart `Isolate` or Rust native async channels. The Flutter UI thread remains at 60/120 FPS.

## Consequences
- **Positive:** UI can be adapted, themed, and redesigned without risk of introducing cryptographic flaws or data corruption.
- **Negative:** Requires strict schema coordination between Rust data structs and Dart generated models.
