//! JNI bridge for the Android app.
//!
//! Implements the native methods of this Kotlin object (`PsmNative.kt`):
//!
//! ```kotlin
//! package io.psmanager.core
//!
//! object PsmNative {
//!     init { System.loadLibrary("psm_android") }
//!
//!     /** Argon2id; slow (64 MiB). `secret` is UTF-8 so the caller can wipe it. */
//!     @JvmStatic external fun deriveRootKey(identity: String, secret: ByteArray): ByteArray
//!     @JvmStatic external fun fingerprint(rootKey: ByteArray): String
//!     /** `account` may be empty; `length` 0 selects the profile default. */
//!     @JvmStatic external fun generate(
//!         rootKey: ByteArray, site: String, account: String,
//!         generation: Long, profile: String, length: Int,
//!     ): String
//!     @JvmStatic external fun normalizeSite(site: String): String
//!     @JvmStatic external fun normalizeText(text: String): String
//!     /** Number of built-in test vectors checked; throws if any mismatch. */
//!     @JvmStatic external fun selftest(): Int
//! }
//! ```
//!
//! Invalid input throws `IllegalArgumentException` with a readable message.

#![expect(unsafe_code, reason = "JNI entry points must be exported unmangled")]

use jni::errors::{Error as JniError, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JClass, JString};
use jni::strings::{JNIStr, JNIString};
use jni::sys::{jint, jlong};
use jni::{Env, EnvUnowned, jni_str};
use psm_core::Zeroizing;
use psm_core::v1::{self, Policy, Profile, Request, RootKey, normalize};

type Result<T> = std::result::Result<T, JniError>;

/// Throws a Java exception; the returned error tells jni-rs one is pending.
fn throw(env: &mut Env, class: &'static JNIStr, message: &str) -> JniError {
    match env.throw_new(class, JNIString::new(message)) {
        Ok(()) => JniError::JavaException,
        Err(e) => e,
    }
}

fn invalid(env: &mut Env, message: &str) -> JniError {
    throw(env, jni_str!("java/lang/IllegalArgumentException"), message)
}

fn root_key(env: &mut Env, bytes: &JByteArray) -> Result<RootKey> {
    let bytes = Zeroizing::new(env.convert_byte_array(bytes)?);
    let Ok(bytes) = <&[u8; 32]>::try_from(bytes.as_slice()) else {
        return Err(invalid(env, "root key must be 32 bytes"));
    };
    Ok(RootKey::from_bytes(bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_deriveRootKey<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    identity: JString<'local>,
    secret: JByteArray<'local>,
) -> JByteArray<'local> {
    env.with_env(|env| -> Result<_> {
        let identity = identity.try_to_string(env)?;
        let secret = Zeroizing::new(env.convert_byte_array(&secret)?);
        let Ok(secret) = std::str::from_utf8(&secret) else {
            return Err(invalid(env, "master secret is not valid UTF-8"));
        };
        let key = RootKey::derive(&identity, secret).map_err(|e| invalid(env, &e.to_string()))?;
        env.byte_array_from_slice(key.as_bytes())
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_fingerprint<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
) -> JString<'local> {
    env.with_env(|env| -> Result<_> {
        let fingerprint = root_key(env, &key)?.fingerprint();
        JString::new(env, fingerprint)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_generate<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    site: JString<'local>,
    account: JString<'local>,
    generation: jlong,
    profile: JString<'local>,
    length: jint,
) -> JString<'local> {
    env.with_env(|env| -> Result<_> {
        let key = root_key(env, &key)?;
        let site = site.try_to_string(env)?;
        let account = account.try_to_string(env)?;
        let Ok(generation) = u32::try_from(generation) else {
            return Err(invalid(env, "generation must be between 1 and 4294967295"));
        };
        let profile = Profile::from_name(&profile.try_to_string(env)?)
            .map_err(|e| invalid(env, &e.to_string()))?;
        let length = match u32::try_from(length) {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => return Err(invalid(env, "length must not be negative")),
        };
        let policy = Policy::new(profile, length).map_err(|e| invalid(env, &e.to_string()))?;
        let request = Request {
            site: &site,
            account: &account,
            generation,
            policy,
        };
        let password = key
            .password(&request)
            .map_err(|e| invalid(env, &e.to_string()))?;
        JString::new(env, password.as_str())
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_normalizeSite<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    site: JString<'local>,
) -> JString<'local> {
    env.with_env(|env| -> Result<_> {
        let site = normalize::site(&site.try_to_string(env)?);
        JString::new(env, site)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_normalizeText<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> JString<'local> {
    env.with_env(|env| -> Result<_> {
        let text = normalize::text(&text.try_to_string(env)?);
        JString::new(env, text)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_psmanager_core_PsmNative_selftest<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jint {
    env.with_env(|env| -> Result<_> {
        v1::selftest()
            .and_then(|checked| jint::try_from(checked).map_err(|e| e.to_string()))
            .map_err(|e| {
                let class = jni_str!("java/lang/IllegalStateException");
                throw(env, class, &format!("self-test failed: {e}"))
            })
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}
