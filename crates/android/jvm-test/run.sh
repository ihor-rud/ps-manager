#!/bin/sh
# Builds the JNI library for this machine and exercises it from a desktop JVM,
# so the bridge can be tested without an Android device.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cargo build --quiet --manifest-path "$root/Cargo.toml" -p psm-android
classes=$(mktemp -d)
trap 'rm -rf "$classes"' EXIT
javac -d "$classes" "$root"/crates/android/jvm-test/io/psmanager/core/*.java
java -Xcheck:jni -Djava.library.path="$root/target/debug" -cp "$classes" io.psmanager.core.SmokeTest
