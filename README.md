# ps-manager

A stateless, offline password generator. From a memorized master secret and a
few facts you already know about an account, it reconstructs the same password
on Windows, Linux or Android, with no vault, no sync, no account and no network.

> **Status: pre-release.** The v1 algorithm in [spec/SPEC-v1.md](spec/SPEC-v1.md)
> is a draft and may still change. Don't use it for important accounts until the
> spec is marked *Frozen*.

## How it works

```
identity + master secret --Argon2id (64 MiB, t=3, p=4)--> root key      (once per session)
root key + site + account + generation + profile + length --HMAC-SHA256--> site key
site key --HMAC-SHA256 counter stream--> unbiased rejection sampling --> password
```

The spec defines every normalization rule, label and byte so the algorithm can
be re-implemented from the document alone. [spec/vectors-v1.json](spec/vectors-v1.json)
holds the test vectors. [reference/psm_ref.py](reference/psm_ref.py) is a second,
independent implementation written from the spec, and it reproduces every vector.

For each account, you need to remember:

| Input | When you need it |
|---|---|
| site | always, e.g. `github.com` (URLs are fine; `https://www.GitHub.com/login` is the same site) |
| account | only if you have more than one account on that site |
| generation | only after you've rotated that password |
| profile / length | only if the site rejects the default (`standard`, 24 characters) |

The 4-character **fingerprint** shown after you enter the master secret should
always be the same. If it's different, you mistyped the secret or your identity.

## Layout

| Path | What |
|---|---|
| `spec/` | Algorithm specification and test vectors |
| `crates/core` | `psm-core`: the algorithm, versioned by module (`psm_core::v1`) |
| `crates/cli` | `psm`: command-line app for Linux and Windows |
| `crates/android` | `psm-android`: JNI bridge (`libpsm_android.so`) for the Android app |
| `reference/` | Independent Python implementation, also usable for recovery |

## Command line

```sh
cargo build --release -p psm          # produces target/release/psm (psm.exe on Windows)

psm generate github.com               # asks for identity and master secret
psm g github.com -a alice@example.com -g 2
psm g oldbank.example -p legacy -l 12
psm policies
psm normalize "https://www.GitHub.com/login"
psm selftest                          # check this build against built-in vectors
```

Set `PSM_IDENTITY` to skip the identity prompt. The password goes to stdout and
everything else to stderr, so `psm g github.com | wl-copy` (or `| clip` on
Windows) copies only the password.

## Android

The Android app will call the shared Rust core through JNI, so every platform
runs the same code. To build the native library, you need the NDK and
[cargo-ndk](https://github.com/bbqsrc/cargo-ndk):

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo make android-build    # arm64-v8a, armeabi-v7a and x86_64 into target/jniLibs
```

The Kotlin side of the interface is documented at the top of
[crates/android/src/lib.rs](crates/android/src/lib.rs).

## Development

Tools:

```sh
rustup toolchain install stable nightly     # nightly runs rustfmt and clippy
rustup target add --toolchain nightly aarch64-linux-android x86_64-pc-windows-gnu
cargo install --locked cargo-make cargo-audit cargo-ndk taplo-cli
```

The Android tasks need the NDK: `export ANDROID_NDK_HOME=/path/to/android-ndk`.
`jni-test` needs a JDK, and `reference` needs Python 3 with `cryptography`.

| Command | What it does |
|---|---|
| `cargo make format` | Format Rust (nightly rustfmt, [.rustfmt.toml](.rustfmt.toml)) and TOML ([taplo.toml](taplo.toml)) |
| `cargo make format-check` | Check formatting without changing files |
| `cargo make clippy` | Nightly clippy for Linux, Windows and Android targets |
| `cargo make audit` | Check dependencies against the RustSec advisory database |
| `cargo make test` | Unit tests and every test vector |
| `cargo make selftest` | Run `psm selftest` from a release build |
| `cargo make reference` | Recompute all vectors with the independent Python implementation |
| `cargo make jni-test` | Call the JNI bridge from a desktop JVM |
| `cargo make build` / `android-build` | Release CLI / Android libraries in `target/jniLibs` |
| `cargo make ci` | All of the above, as CI runs them |

The lints in [Cargo.toml](Cargo.toml) are strict (pedantic, nursery, no
`unwrap`/`expect`/`panic` outside tests). Where a lint has to give way, use
`#[expect(lint, reason = "...")]`, not `allow`.
