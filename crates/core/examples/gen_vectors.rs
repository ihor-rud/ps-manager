//! Writes `spec/vectors-v1.json` to stdout.
//!
//! Run once when the vector set changes, then cross-check the file with the
//! independent implementation in `reference/psm_ref.py`. Never regenerate
//! the file to make a failing test pass: a changed output is a broken
//! algorithm.
//!
//!     cargo run --release -p psm-core --example gen_vectors > spec/vectors-v1.json

#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "development tool: prints the vectors and stops on any error"
)]

use std::fmt::Write;

use psm_core::v1::{self, Policy, Profile, Request, RootKey, normalize};
use serde_json::{Value, json};

// Non-ASCII inputs are written as escapes so that every file stays ASCII.
const TEXT: &[&str] = &[
    "Test User",
    "  Jane \u{00A0}\t DOE \n",
    "\u{FF21}\u{FF22}\u{FF23}",
    "\u{FB01}le",
    "\u{1D2C}",
    "\u{212A}",
    "\u{00DF}",
    "X\u{03A3}",
    "\u{0130}X",
    "\u{01C5}X",
    "\u{216B}",
    "\u{3000}",
    "Alice@Example.COM",
    "a\u{1680}b",
    "a\u{200B}b",
];

const SITE: &[&str] = &[
    "github.com",
    "GitHub.com",
    "https://www.github.com/login?next=/x#top",
    "user:pass@www.GITHUB.com:8443",
    "github.com.",
    "\u{FF47}\u{FF49}\u{FF54}\u{FF48}\u{FF55}\u{FF42}\u{FF0E}\u{FF43}\u{FF4F}\u{FF4D}",
    "HTTP://Example.com:80/",
    "accounts.example.com",
    "www.",
    "www.www.example.com",
    "localhost:3000",
    "example.com:",
    "[::1]:8080",
    "\u{00C4}\u{00D6}.example",
    "android://com.example.app",
    "mailto:me@example.com",
    "My Bank",
    "https://",
    "   ",
];

const SECRET: &[&str] = &["e\u{0301}", " Mixed Case \u{FB01} ", "\u{212B}"];

struct RootInput {
    identity: &'static str,
    secret: &'static str,
    cases: &'static [(&'static str, &'static str, u32, Profile, Option<u32>)],
}

const ROOTS: &[RootInput] = &[
    RootInput {
        identity: "Test User",
        secret: "correct horse battery staple",
        cases: &[
            ("github.com", "", 1, Profile::Standard, None),
            (
                "https://www.GitHub.com/login?return_to=%2F",
                "",
                1,
                Profile::Standard,
                None,
            ),
            (
                "github.com",
                "alice@example.com",
                1,
                Profile::Standard,
                None,
            ),
            (
                "github.com",
                "Alice@Example.com",
                1,
                Profile::Standard,
                None,
            ),
            (
                "github.com",
                "alice@example.com",
                2,
                Profile::Standard,
                None,
            ),
            ("github.com", "", u32::MAX, Profile::Standard, None),
            ("github.com", "", 1, Profile::Alphanumeric, None),
            ("github.com", "", 1, Profile::Legacy, None),
            ("github.com", "", 1, Profile::Pin, None),
            ("github.com", "", 1, Profile::Pin, Some(4)),
            ("github.com", "", 1, Profile::Standard, Some(8)),
            ("github.com", "", 1, Profile::Standard, Some(64)),
            ("github.com", "", 1, Profile::Legacy, Some(8)),
            ("example.com", "", 1, Profile::Legacy, Some(8)),
            ("example.com", "", 2, Profile::Legacy, Some(8)),
            ("example.com", "", 3, Profile::Standard, Some(8)),
            ("accounts.google.com", "", 1, Profile::Standard, None),
            ("\u{00C4}\u{00D6}.example", "", 1, Profile::Standard, None),
            (
                "bank.example",
                "USER\u{00A0}NAME",
                1,
                Profile::Legacy,
                Some(12),
            ),
        ],
    },
    RootInput {
        identity: "  Jane   DOE\u{00A0}",
        secret: "\u{00E4}\u{00F6}\u{00FC} \u{20AC}100 \u{2713}",
        cases: &[
            ("github.com", "", 1, Profile::Standard, None),
            (
                "WWW.\u{00C5}\u{00D8}.EXAMPLE",
                "",
                1,
                Profile::Standard,
                None,
            ),
            ("mail.example", "jane", 3, Profile::Alphanumeric, Some(20)),
        ],
    },
    // The same secret in decomposed and precomposed form must agree.
    RootInput {
        identity: "Test User",
        secret: "correct horse e\u{0301}",
        cases: &[("example.com", "", 1, Profile::Standard, None)],
    },
    RootInput {
        identity: "Test User",
        secret: "correct horse \u{00E9}",
        cases: &[("example.com", "", 1, Profile::Standard, None)],
    },
];

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|&b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
        .map(char::from)
        .collect()
}

/// JSON allows `\uXXXX` escapes in any string; using them keeps the file ASCII.
fn ascii_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                write!(out, "\\u{unit:04x}").unwrap();
            }
        }
    }
    out
}

fn normalization(function: &str, inputs: &[&str], f: impl Fn(&str) -> String) -> Vec<Value> {
    inputs
        .iter()
        .map(|input| json!({ "function": function, "input": input, "output": f(input) }))
        .collect()
}

fn main() {
    let mut cases = normalization("text", TEXT, normalize::text);
    cases.extend(normalization("site", SITE, normalize::site));
    cases.extend(normalization("secret", SECRET, |s| {
        normalize::secret(s).as_str().to_owned()
    }));

    let roots: Vec<Value> = ROOTS
        .iter()
        .map(|root| {
            let key = RootKey::derive(root.identity, root.secret).unwrap();
            let passwords: Vec<Value> = root
                .cases
                .iter()
                .map(|&(site, account, generation, profile, length)| {
                    let policy = Policy::new(profile, length).unwrap();
                    let request = Request {
                        site,
                        account,
                        generation,
                        policy,
                    };
                    json!({
                        "site": site,
                        "account": account,
                        "generation": generation,
                        "profile": profile.name(),
                        "length": policy.length(),
                        "normalized_site": normalize::site(site),
                        "normalized_account": normalize::text(account),
                        "site_key": hex(&*key.site_key(&request).unwrap()),
                        "password": key.password(&request).unwrap().as_str(),
                    })
                })
                .collect();
            json!({
                "identity": root.identity,
                "secret": root.secret,
                "normalized_identity": normalize::text(root.identity),
                "salt": hex(&v1::salt(root.identity).unwrap()),
                "root_key": hex(key.as_bytes()),
                "fingerprint": key.fingerprint(),
                "passwords": passwords,
            })
        })
        .collect();

    let doc = json!({
        "algorithm": v1::ID,
        "note": "Normalization outputs that are empty mean the input is rejected for identity, secret and site.",
        "argon2id": {
            "version": 19,
            "memory_kib": v1::ARGON2_MEMORY_KIB,
            "passes": v1::ARGON2_PASSES,
            "lanes": v1::ARGON2_LANES,
            "tag_length": 32,
        },
        "normalization": cases,
        "roots": roots,
    });
    println!(
        "{}",
        ascii_json(&serde_json::to_string_pretty(&doc).unwrap())
    );
}
