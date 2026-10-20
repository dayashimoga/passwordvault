# Setup & Environment Guide

## 1. Prerequisites

### Rust Toolchain
- Rust Stable 1.80+ (or latest stable, e.g. 1.99.1+)
- Cargo, Rustfmt, and Clippy:
  ```powershell
  rustup toolchain install stable
  rustup component add clippy rustfmt
  ```

### Flutter & Dart SDK
- Flutter 3.24+ (Dart 3.5+)
- Ensure `flutter` is added to your environment `PATH`.
- Verify with:
  ```powershell
  flutter doctor
  ```

### Platform-Specific SDKs
- **Windows:** Visual Studio 2022 C++ Build Tools or MinGW GCC toolchain (`x86_64-pc-windows-gnu`).
- **Android:** Android Studio, Android SDK Platform 34+, NDK (version 26+), CMake 3.22+.
- **iOS / macOS:** Xcode 15+ with Command Line Tools (macOS only).
- **Linux:** `build-essential`, `pkg-config`, `libssl-dev`, `libayatana-appindicator3-dev`.

---

## 2. Workspace Initialization

Clone or open the repository:
```powershell
cd j:\rustpwdvault
```

Build the Rust Core workspace:
```powershell
cd core
cargo build --release
cargo test
```

Build or run Flutter application:
```powershell
cd ../apps/flutter
flutter pub get
flutter run -d windows
```

---

## 3. Containerized Build & Test (Podman / Docker)

For hermetic, reproducible builds without installing local dependencies, use the provided Docker/Podman scripts in `/scripts/`:
```bash
./scripts/docker_build.sh
./scripts/docker_test.sh
```
