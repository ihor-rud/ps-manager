//! Built-in known-answer test, so any build on any device can check itself.
//!
//! These cases are a subset of `spec/vectors-v1.json`; a unit test keeps the
//! two in agreement.

use super::{Policy, Profile, Request, RootKey};

struct Case {
    site: &'static str,
    account: &'static str,
    generation: u32,
    profile: Profile,
    length: u32,
    password: &'static str,
}

struct Root {
    identity: &'static str,
    secret: &'static str,
    fingerprint: &'static str,
    cases: &'static [Case],
}

const ROOTS: &[Root] = &[
    Root {
        identity: "Test User",
        secret: "correct horse battery staple",
        fingerprint: "FZHC",
        cases: &[
            Case {
                site: "github.com",
                account: "",
                generation: 1,
                profile: Profile::Standard,
                length: 24,
                password: "=0tL!yWs0M2$LJTag7W?H%G9",
            },
            Case {
                site: "github.com",
                account: "alice@example.com",
                generation: 2,
                profile: Profile::Standard,
                length: 24,
                password: "oF*mdnl3C37KNcqv@%=5U8sQ",
            },
            Case {
                site: "github.com",
                account: "",
                generation: 1,
                profile: Profile::Alphanumeric,
                length: 24,
                password: "5auyVzwOpOAvAB4gWEmWgqxs",
            },
            Case {
                site: "example.com",
                account: "",
                generation: 2,
                profile: Profile::Legacy,
                length: 8,
                password: "^5MpYEPJ",
            },
            Case {
                site: "github.com",
                account: "",
                generation: 1,
                profile: Profile::Pin,
                length: 6,
                password: "780679",
            },
        ],
    },
    Root {
        identity: "  Jane   DOE\u{00A0}",
        secret: "\u{00E4}\u{00F6}\u{00FC} \u{20AC}100 \u{2713}",
        fingerprint: "2CK2",
        cases: &[Case {
            site: "WWW.\u{00C5}\u{00D8}.EXAMPLE",
            account: "",
            generation: 1,
            profile: Profile::Standard,
            length: 24,
            password: "8m1SP*uoqd-w_ICI1vyeGvT&",
        }],
    },
];

/// Recomputes the built-in vectors; returns how many passwords were checked.
pub fn selftest() -> Result<usize, String> {
    let mut checked = 0;
    for root in ROOTS {
        let key = RootKey::derive(root.identity, root.secret).map_err(|e| e.to_string())?;
        let fingerprint = key.fingerprint();
        if fingerprint != root.fingerprint {
            return Err(format!(
                "fingerprint for identity {:?}: expected {}, got {fingerprint}",
                root.identity, root.fingerprint
            ));
        }
        for case in root.cases {
            let policy = Policy::new(case.profile, Some(case.length)).map_err(|e| e.to_string())?;
            let request = Request {
                site: case.site,
                account: case.account,
                generation: case.generation,
                policy,
            };
            let password = key.password(&request).map_err(|e| e.to_string())?;
            if password.as_str() != case.password {
                return Err(format!(
                    "password for site {:?} (account {:?}, generation {}, {} {}) does not match",
                    case.site, case.account, case.generation, case.profile, case.length
                ));
            }
            checked += 1;
        }
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_cases_are_published_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../../spec/vectors-v1.json")).unwrap();
        for root in ROOTS {
            let published = vectors["roots"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["identity"] == root.identity && r["secret"] == root.secret)
                .expect("root is in vectors-v1.json");
            assert_eq!(published["fingerprint"], root.fingerprint);
            for case in root.cases {
                assert!(
                    published["passwords"].as_array().unwrap().iter().any(|p| {
                        p["site"] == case.site
                            && p["account"] == case.account
                            && p["generation"] == case.generation
                            && p["profile"] == case.profile.name()
                            && p["length"] == case.length
                            && p["password"] == case.password
                    }),
                    "{} is not in vectors-v1.json",
                    case.password
                );
            }
        }
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), Ok(6));
    }
}
