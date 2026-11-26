#!/usr/bin/env bash
# Builds libbitaid_jni.so for Android (arm64-v8a + x86_64) via cargo-ndk and places them in jniLibs.
# Run from WSL on the build PC with ANDROID_NDK_HOME set.
# Keeps Cargo.lock pinned (cc 1.7.0 — do NOT run `cargo update`).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo ndk \
  -t arm64-v8a \
  -t x86_64 \
  -o android/app/src/main/jniLibs \
  build --release -p bitaid-jni

echo "Built JNI libraries under android/app/src/main/jniLibs"
