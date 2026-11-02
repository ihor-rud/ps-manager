//! Checks this implementation against `spec/vectors-v1.json`.

#![cfg(test)]

use psm_core::v1::{self, Policy, Profile, Request, RootKey, normalize};
use serde_json::Value;

fn vectors() -> Value {
    let text = include_str!("../../../spec/vectors-v1.json");
    serde_json::from_str(text).expect("vectors-v1.json is valid JSON")
}

fn str_of<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing string {field}"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|&b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
        .map(char::from)
        .collect()
}

#[test]
fn header_matches_constants() {
    let v = vectors();
    assert_eq!(str_of(&v, "algorithm"), v1::ID);
    assert_eq!(v["argon2id"]["memory_kib"], v1::ARGON2_MEMORY_KIB);
    assert_eq!(v["argon2id"]["passes"], v1::ARGON2_PASSES);
    assert_eq!(v["argon2id"]["lanes"], v1::ARGON2_LANES);
}

#[test]
fn normalization() {
    let v = vectors();
    for case in v["normalization"].as_array().unwrap() {
        let input = str_of(case, "input");
        let actual = match str_of(case, "function") {
            "text" => normalize::text(input),
            "site" => normalize::site(input),
            "secret" => normalize::secret(input).as_str().to_owned(),
            other => panic!("unknown normalization function {other}"),
        };
        assert_eq!(actual, str_of(case, "output"), "{case}");
    }
}

#[test]
fn derivations() {
    let v = vectors();
    for root in v["roots"].as_array().unwrap() {
        let identity = str_of(root, "identity");
        assert_eq!(
            normalize::text(identity),
            str_of(root, "normalized_identity")
        );
        assert_eq!(hex(&v1::salt(identity).unwrap()), str_of(root, "salt"));

        let key = RootKey::derive(identity, str_of(root, "secret")).unwrap();
        assert_eq!(hex(key.as_bytes()), str_of(root, "root_key"), "{identity}");
        assert_eq!(key.fingerprint(), str_of(root, "fingerprint"));

        for case in root["passwords"].as_array().unwrap() {
            let profile = Profile::from_name(str_of(case, "profile")).unwrap();
            let length = u32::try_from(case["length"].as_u64().unwrap()).unwrap();
            let request = Request {
                site: str_of(case, "site"),
                account: str_of(case, "account"),
                generation: u32::try_from(case["generation"].as_u64().unwrap()).unwrap(),
                policy: Policy::new(profile, Some(length)).unwrap(),
            };
            assert_eq!(
                normalize::site(request.site),
                str_of(case, "normalized_site")
            );
            assert_eq!(
                normalize::text(request.account),
                str_of(case, "normalized_account")
            );
            assert_eq!(
                hex(&*key.site_key(&request).unwrap()),
                str_of(case, "site_key"),
                "{case}"
            );
            assert_eq!(
                key.password(&request).unwrap().as_str(),
                str_of(case, "password"),
                "{case}"
            );
        }
    }
}
