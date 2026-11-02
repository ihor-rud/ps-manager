# ps-manager

A stateless, offline password generator. From a memorized master secret and a
few facts you already know about an account, it reconstructs the same password
on Windows, Linux, or a phone's browser, with no vault, no sync, no account and
no network.

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
| `crates/web` | `psm-web`: the core compiled to WebAssembly, and the browser app (`psm.html`) |
| `reference/` | Independent Python implementation, also usable for recovery |

## Command line

```sh
cargo build --release -p psm          # produces target/release/psm (psm.exe on Windows)

psm generate github.com               # asks for identity and master secret
psm g github.com -a alice@example.com -g 2
psm g oldbank.example -p legacy -l 12
psm g github.com --clip               # copy instead of print; cleared after 20 s
psm session --clip                    # enter the secret once, then one site per line
psm policies
psm normalize "https://www.GitHub.com/login"
psm selftest                          # check this build against built-in vectors
psm help generate                     # every option
```

Set `PSM_IDENTITY` to skip the identity prompt. Without `--clip`, the password
goes to stdout and everything else to stderr.

With `--clip`, the password is copied with the platform's "don't keep this"
hints: Windows keeps it out of clipboard history and cloud sync, and on Linux
it is marked for password-aware clipboard managers and never handed to one when
`psm` exits. It is cleared after `--clear-after` seconds (default 20) or on
Ctrl+C, but only if the clipboard still holds it.

In a session, each line takes the options of `psm generate`, for example
`github.com -a alice -g 2` or `"My Bank" -p pin`; add `-c` to copy one password.
`exit` or Ctrl+D ends the session and clears the clipboard.

## Phone and browser

`psm.html` is the whole app in one file: the same Rust core compiled to
WebAssembly, plus a small page around it. Copy it to your phone (or any
computer) and open it in Chrome or Firefox from the Files app. It needs no
installation and no internet connection.

```sh
cargo make web-build        # writes target/web/psm.html
```

The page's Content-Security-Policy admits only its own inline code, by hash,
and blocks every network request, so it cannot send anything anywhere. The root
key stays inside WebAssembly memory and is wiped when you lock the page, when
you close it, or after 5 minutes without use. Passwords are hidden until you
tap Show and disappear after a minute; a copied password is cleared from the
clipboard after 20 seconds while the page is open. Use **Self-test** to check
that a browser computes the published vectors.

A browser page has limits a native app would not: it cannot block screenshots,
the browser may offer to save the master secret (decline), and clipboard
clearing only works while the page is in front. Anyone who can change the file
can change what it does, so keep it where other apps cannot write, and compare
it with `SHA256SUMS` from the release when you copy it.

## Development

Tools:

```sh
rustup toolchain install stable nightly     # nightly runs rustfmt and clippy
rustup target add wasm32-unknown-unknown
rustup target add --toolchain nightly wasm32-unknown-unknown x86_64-pc-windows-gnu
cargo install --locked cargo-make cargo-audit taplo-cli
cargo install --locked wasm-bindgen-cli --version "$(cargo pkgid wasm-bindgen | sed 's/.*@//')"
```

`wasm-bindgen-cli` must be the same version as the `wasm-bindgen` crate in
Cargo.lock. The web tasks need Python 3 and Node.js 22 or later,
`web-browser-test` needs Firefox, and `reference` needs Python's `cryptography`.

| Command | What it does |
|---|---|
| `cargo make format` | Format Rust (nightly rustfmt, [.rustfmt.toml](.rustfmt.toml)) and TOML ([taplo.toml](taplo.toml)) |
| `cargo make format-check` | Check formatting without changing files |
| `cargo make clippy` | Nightly clippy for Linux, Windows and WebAssembly targets |
| `cargo make audit` | Check dependencies against the RustSec advisory database |
| `cargo make test` | Unit tests and every test vector |
| `cargo make selftest` | Run `psm selftest` from a release build |
| `cargo make reference` | Recompute all vectors with the independent Python implementation |
| `cargo make web-test` | Run every vector through the WebAssembly core inside the built `psm.html` |
| `cargo make web-browser-test` | Use `psm.html` in headless Firefox: unlock, generate, self-test, lock |
| `cargo make build` / `web-build` | Release CLI / `target/web/psm.html` |
| `cargo make dist [TARGET\|web]` | Release file in `target/dist`, see [scripts/dist.sh](scripts/dist.sh) |
| `cargo make ci` | All of the above, as CI runs them |

The lints in [Cargo.toml](Cargo.toml) are strict (pedantic, nursery, no
`unwrap`/`expect`/`panic` outside tests). Where a lint has to give way, use
`#[expect(lint, reason = "...")]`, not `allow`.

## Releases

Bump `version` in [Cargo.toml](Cargo.toml), then push a matching tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The [release workflow](.github/workflows/release.yml) checks that the tag
matches the version, then builds:

- `psm-<version>-x86_64-unknown-linux-musl.tar.gz`, a static binary for any x86-64 Linux
- `psm-<version>-x86_64-pc-windows-msvc.zip`
- `psm-<version>.html`, the browser app

It opens a **draft** release with these files and a `SHA256SUMS` file. Review
the draft before you publish it. The two archives also contain the spec, the
test vectors and the Python reference implementation, so passwords can be
recovered from an archive alone.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
