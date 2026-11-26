# Bitaid Android App (M4, Signet Prototype)

Minimal Android shell over `bitaid-node` + `bitaid-tor` (`crates/bitaid-jni`). Test chains only.

## Build (WSL on PC)

Prerequisites:
- Rust targets: `rustup target add aarch64-linux-android x86_64-linux-android`
- `cargo install cargo-ndk`
- Android SDK + NDK (`ANDROID_HOME`, `ANDROID_NDK_HOME`)
- JDK 17 + Gradle 8.x

```bash
# 1. Build libbitaid_jni.so for arm64-v8a and x86_64 (do NOT run `cargo update`: keep cc 1.7.0)
sh android/build-native.sh

# 2. Build debug APK
cd android
gradle assembleDebug

# 3. Install on phone/tablet
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Security & Lifecycle Notes
- **Tor SOCKS secret:** stays inside `crates/bitaid-jni`; never crosses JNI into Kotlin or `logcat`.
- **Keys (Step 5):** `KeystoreSecretStore` wraps every secret via Google Tink (`AES256_GCM`, hardware-backed Android Keystore master key, no biometric gate for on-duty alerts, per-file AAD, atomic write under `noBackupFilesDir`, `allowBackup="false"`).
- **Foreground service (Step 4):** declares `specialUse|location` for Android 14+, filters `ConnectivityManager.NetworkCallback` by `Network.networkHandle` before calling `torNetworkChanged()`, and toggles `setTorDormant` with the on-duty switch.
