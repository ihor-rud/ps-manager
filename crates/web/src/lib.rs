//! WebAssembly bindings for the browser app (`psm.html`).
//!
//! The root key stays inside WebAssembly memory: JavaScript only holds a
//! [`Session`] handle, and `session.free()` wipes the key.

use psm_core::v1::{self, Policy, Profile, Request, RootKey, normalize};
use wasm_bindgen::prelude::*;

/// A derived root key, ready to generate passwords.
#[wasm_bindgen]
pub struct Session {
    key: RootKey,
}

#[wasm_bindgen]
impl Session {
    /// Runs Argon2id with 64 MiB of memory; takes about a second.
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &str, secret: &str) -> Result<Self, JsError> {
        let key = RootKey::derive(identity, secret).map_err(error)?;
        Ok(Self { key })
    }

    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint()
    }

    /// `length` 0 selects the profile's default length.
    pub fn password(
        &self,
        site: &str,
        account: &str,
        generation: u32,
        profile: &str,
        length: u32,
    ) -> Result<String, JsError> {
        let profile = Profile::from_name(profile).map_err(error)?;
        let policy = Policy::new(profile, (length != 0).then_some(length)).map_err(error)?;
        let request = Request {
            site,
            account,
            generation,
            policy,
        };
        let password = self.key.password(&request).map_err(error)?;
        Ok(password.as_str().to_owned())
    }
}

/// A password profile, for building the profile picker.
#[wasm_bindgen(getter_with_clone)]
pub struct ProfileInfo {
    pub name: String,
    pub description: String,
    #[wasm_bindgen(js_name = defaultLength)]
    pub default_length: u32,
    #[wasm_bindgen(js_name = minLength)]
    pub min_length: u32,
    #[wasm_bindgen(js_name = maxLength)]
    pub max_length: u32,
}

#[wasm_bindgen]
#[must_use]
pub fn profiles() -> Vec<ProfileInfo> {
    Profile::ALL
        .into_iter()
        .map(|p| ProfileInfo {
            name: p.name().to_owned(),
            description: p.description().to_owned(),
            default_length: p.default_length(),
            min_length: *p.length_range().start(),
            max_length: *p.length_range().end(),
        })
        .collect()
}

#[wasm_bindgen(js_name = normalizeSite)]
#[must_use]
pub fn normalize_site(site: &str) -> String {
    normalize::site(site)
}

#[wasm_bindgen(js_name = normalizeText)]
#[must_use]
pub fn normalize_text(text: &str) -> String {
    normalize::text(text)
}

/// Checks this build against the built-in test vectors; returns how many
/// passwords matched.
#[wasm_bindgen]
pub fn selftest() -> Result<u32, JsError> {
    let checked = v1::selftest().map_err(|e| JsError::new(&e))?;
    u32::try_from(checked).map_err(error)
}

#[wasm_bindgen]
#[must_use]
pub fn algorithm() -> String {
    v1::ID.to_owned()
}

fn error(e: impl std::error::Error) -> JsError {
    JsError::new(&e.to_string())
}
