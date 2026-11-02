//! Algorithm `ps-manager/v1`, as specified in `spec/SPEC-v1.md`.
//!
//! Section numbers in comments refer to that document.

pub mod normalize;
mod policy;
mod selftest;

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, KeyInit, Mac};
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use self::policy::{Policy, Profile};
pub use self::selftest::selftest;

/// The algorithm identifier (section 11).
pub const ID: &str = "ps-manager/v1";

const LABEL_SALT: &[u8] = b"ps-manager/v1/salt";
const LABEL_FINGERPRINT: &[u8] = b"ps-manager/v1/fingerprint";
const LABEL_SITE: &[u8] = b"ps-manager/v1/site";
const LABEL_STREAM: &[u8] = b"ps-manager/v1/stream";

/// Argon2id parameters (section 5).
pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_PASSES: u32 = 3;
pub const ARGON2_LANES: u32 = 4;

// Evaluated at compile time, so an invalid parameter set fails the build.
const ARGON2_PARAMS: Params =
    match Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32)) {
        Ok(params) => params,
        Err(_) => panic!("invalid v1 Argon2 parameters"),
    };

const FINGERPRINT_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    EmptyIdentity,
    EmptySecret,
    EmptySite,
    ZeroGeneration,
    InvalidLength {
        profile: Profile,
        length: u32,
        min: u32,
        max: u32,
    },
    UnknownProfile(String),
    /// A field is 2^32 bytes or longer (section 3).
    InputTooLong,
    /// Argon2 failed, e.g. because 64 MiB could not be allocated.
    KeyDerivation(argon2::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentity => f.write_str("identity is empty"),
            Self::EmptySecret => f.write_str("master secret is empty"),
            Self::EmptySite => f.write_str("site is empty after normalization"),
            Self::ZeroGeneration => f.write_str("generation must be at least 1"),
            Self::InvalidLength {
                profile,
                length,
                min,
                max,
            } => write!(
                f,
                "length {length} is outside {min}..{max} for profile {profile}"
            ),
            Self::UnknownProfile(name) => write!(
                f,
                "unknown profile {name:?} (expected standard, alphanumeric, legacy or pin)"
            ),
            Self::InputTooLong => f.write_str("input is too long"),
            Self::KeyDerivation(e) => write!(f, "key derivation failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// What to derive a password for. Inputs are normalized during derivation.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub site: &'a str,
    pub account: &'a str,
    pub generation: u32,
    pub policy: Policy,
}

impl<'a> Request<'a> {
    /// The default case: no account, generation 1, standard policy.
    #[must_use]
    pub fn new(site: &'a str) -> Self {
        Self {
            site,
            account: "",
            generation: 1,
            policy: Policy::default(),
        }
    }
}

/// The Argon2 salt of section 5. Not secret.
pub fn salt(identity: &str) -> Result<[u8; 32], Error> {
    let identity = normalize::text(identity);
    if identity.is_empty() {
        return Err(Error::EmptyIdentity);
    }
    check_len(&identity)?;
    let mut salt = Sha256::new();
    lp(&mut salt, LABEL_SALT);
    lp(&mut salt, identity.as_bytes());
    Ok(salt.finalize().into())
}

/// `K_root` (section 5). As sensitive as the master secret; wiped on drop.
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Runs Argon2id. Takes about a second and 64 MiB of memory, so derive
    /// once per session and reuse the key for every site.
    pub fn derive(identity: &str, secret: &str) -> Result<Self, Error> {
        let salt = salt(identity)?;
        let secret = normalize::secret(secret);
        if secret.is_empty() {
            return Err(Error::EmptySecret);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, ARGON2_PARAMS)
            .hash_password_into(secret.as_bytes(), &salt, key.as_mut_slice())
            .map_err(Error::KeyDerivation)?;
        Ok(Self(key))
    }

    /// Restores a key previously obtained from [`RootKey::as_bytes`]. Copies,
    /// so the caller stays responsible for wiping `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(bytes);
        Self(key)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 4-character check value of section 6.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let f = hmac(&self.0, |m| lp(m, LABEL_FINGERPRINT));
        f[..4]
            .iter()
            .map(|&b| char::from(FINGERPRINT_ALPHABET[usize::from(b % 32)]))
            .collect()
    }

    /// `K_site` (section 7). Exposed for test vectors and diagnostics.
    pub fn site_key(&self, request: &Request) -> Result<Zeroizing<[u8; 32]>, Error> {
        let site = normalize::site(request.site);
        if site.is_empty() {
            return Err(Error::EmptySite);
        }
        if request.generation == 0 {
            return Err(Error::ZeroGeneration);
        }
        let account = normalize::text(request.account);
        check_len(&site)?;
        check_len(&account)?;
        Ok(hmac(&self.0, |m| {
            lp(m, LABEL_SITE);
            lp(m, site.as_bytes());
            lp(m, account.as_bytes());
            u32be(m, request.generation);
            lp(m, request.policy.profile().name().as_bytes());
            u32be(m, request.policy.length());
        }))
    }

    /// The password of section 10.
    pub fn password(&self, request: &Request) -> Result<Zeroizing<String>, Error> {
        let profile = request.policy.profile();
        let classes = profile.classes();
        let alphabet = profile.alphabet().into_bytes();
        let length = request.policy.length() as usize;
        let mut stream = Stream::new(self.site_key(request)?);
        let mut password = Zeroizing::new(String::with_capacity(length));
        loop {
            password.clear();
            for _ in 0..length {
                password.push(char::from(alphabet[stream.uniform(alphabet.len())]));
            }
            if classes
                .iter()
                .all(|class| password.chars().any(|c| class.contains(c)))
            {
                return Ok(password);
            }
        }
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey(..)")
    }
}

/// The byte stream `R` of section 8.
struct Stream {
    key: Zeroizing<[u8; 32]>,
    block: Zeroizing<[u8; 32]>,
    next_block: u32,
    pos: usize,
}

impl Stream {
    fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            key,
            block: Zeroizing::new([0; 32]),
            next_block: 0,
            pos: 32,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.pos == self.block.len() {
            let i = self.next_block;
            self.block = hmac(&self.key, |m| {
                lp(m, LABEL_STREAM);
                u32be(m, i);
            });
            #[expect(
                clippy::expect_used,
                reason = "a password needs hundreds of bytes, not 128 GiB"
            )]
            let next = i.checked_add(1).expect("stream exhausted after 128 GiB");
            self.next_block = next;
            self.pos = 0;
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }

    /// `Uniform(n)` of section 8.
    fn uniform(&mut self, n: usize) -> usize {
        debug_assert!((1..=256).contains(&n));
        let limit = 256 - 256 % n;
        loop {
            let b = usize::from(self.byte());
            if b < limit {
                return b % n;
            }
        }
    }
}

fn hmac(key: &[u8; 32], message: impl FnOnce(&mut HmacSha256)) -> Zeroizing<[u8; 32]> {
    #[expect(clippy::expect_used, reason = "HMAC accepts keys of any length")]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    message(&mut mac);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn u32be(h: &mut impl Update, n: u32) {
    h.update(&n.to_be_bytes());
}

/// Rejects fields that `lp` cannot encode (section 3).
fn check_len(field: &str) -> Result<(), Error> {
    u32::try_from(field.len())
        .map(drop)
        .map_err(|_| Error::InputTooLong)
}

/// `lp(s)` of section 2.
fn lp(h: &mut impl Update, bytes: &[u8]) {
    #[expect(
        clippy::expect_used,
        reason = "inputs pass check_len and labels are constants"
    )]
    let len = u32::try_from(bytes.len()).expect("fields are shorter than 2^32 bytes (section 3)");
    u32be(h, len);
    h.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RootKey {
        RootKey::from_bytes(&[7; 32])
    }

    #[test]
    fn every_password_satisfies_its_policy() {
        let key = key();
        for profile in Profile::ALL {
            for length in [
                *profile.length_range().start(),
                profile.default_length(),
                64,
            ] {
                let policy = Policy::new(profile, Some(length)).unwrap();
                for generation in 1..=50 {
                    let request = Request {
                        generation,
                        policy,
                        ..Request::new("example.com")
                    };
                    let password = key.password(&request).unwrap();
                    assert_eq!(password.len(), length as usize);
                    for class in profile.classes() {
                        assert!(password.chars().any(|c| class.contains(c)));
                    }
                    assert!(password.chars().all(|c| profile.alphabet().contains(c)));
                }
            }
        }
    }

    #[test]
    fn inputs_are_independent() {
        let key = key();
        let base = Request::new("example.com");
        let variants = [
            Request::new("example.org"),
            Request {
                account: "alice",
                ..base
            },
            Request {
                generation: 2,
                ..base
            },
            Request {
                policy: Policy::new(Profile::Alphanumeric, None).unwrap(),
                ..base
            },
            Request {
                policy: Policy::new(Profile::Standard, Some(25)).unwrap(),
                ..base
            },
        ];
        let base_key = key.site_key(&base).unwrap();
        for v in variants {
            assert_ne!(*key.site_key(&v).unwrap(), *base_key, "{v:?}");
        }
        let same = Request::new("https://www.EXAMPLE.com/login");
        assert_eq!(*key.site_key(&same).unwrap(), *base_key);
    }

    #[test]
    fn invalid_requests_are_rejected() {
        let key = key();
        assert_eq!(
            key.password(&Request::new("https:///")).unwrap_err(),
            Error::EmptySite
        );
        let request = Request {
            generation: 0,
            ..Request::new("example.com")
        };
        assert_eq!(key.password(&request).unwrap_err(), Error::ZeroGeneration);
        assert_eq!(
            RootKey::derive(" \t", "x").unwrap_err(),
            Error::EmptyIdentity
        );
        assert_eq!(RootKey::derive("me", "").unwrap_err(), Error::EmptySecret);
    }

    #[test]
    fn uniform_is_unbiased_over_a_full_byte_cycle() {
        // With n = 75, bytes 225..=255 are rejected, so each value has
        // exactly three accepted preimages.
        let limit = 256 - 256 % 75;
        let mut counts = [0u32; 75];
        for b in 0..limit {
            counts[b % 75] += 1;
        }
        assert!(counts.iter().all(|&c| c == 3));
    }
}
