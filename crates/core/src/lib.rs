//! Deterministic, stateless password derivation.
//!
//! Each algorithm version lives in its own module and never changes once
//! frozen; see `spec/SPEC-v1.md` for the normative description of [`v1`].
//! Callers must always name the version they use, so an upgrade is never
//! silent.

#![forbid(unsafe_code)]

pub mod v1;

pub use zeroize::Zeroizing;
