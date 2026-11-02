//! Password policy profiles (spec section 9).

use std::fmt;
use std::ops::RangeInclusive;

use super::Error;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &str = "0123456789";
const SYMBOL: &str = "!#$%&*+-=?@^_";
const SYMBOL_BASIC: &str = "!@#$%^&*";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    Standard,
    Alphanumeric,
    Legacy,
    Pin,
}

impl Profile {
    pub const ALL: [Self; 4] = [Self::Standard, Self::Alphanumeric, Self::Legacy, Self::Pin];

    /// The name that enters the derivation; part of the frozen algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Alphanumeric => "alphanumeric",
            Self::Legacy => "legacy",
            Self::Pin => "pin",
        }
    }

    /// Parses a profile name, ignoring ASCII case.
    pub fn from_name(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|p| p.name().eq_ignore_ascii_case(name.trim()))
            .ok_or_else(|| Error::UnknownProfile(name.to_owned()))
    }

    #[must_use]
    pub const fn default_length(self) -> u32 {
        match self {
            Self::Standard | Self::Alphanumeric => 24,
            Self::Legacy => 16,
            Self::Pin => 6,
        }
    }

    #[must_use]
    pub const fn length_range(self) -> RangeInclusive<u32> {
        match self {
            Self::Pin => 4..=64,
            Self::Standard | Self::Alphanumeric | Self::Legacy => 8..=64,
        }
    }

    /// Character classes in alphabet order.
    pub(crate) const fn classes(self) -> &'static [&'static str] {
        match self {
            Self::Standard => &[LOWER, UPPER, DIGIT, SYMBOL],
            Self::Alphanumeric => &[LOWER, UPPER, DIGIT],
            Self::Legacy => &[LOWER, UPPER, DIGIT, SYMBOL_BASIC],
            Self::Pin => &[DIGIT],
        }
    }

    /// The characters a password of this profile may contain.
    #[must_use]
    pub fn alphabet(self) -> String {
        self.classes().concat()
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Standard => "letters, digits and symbols !#$%&*+-=?@^_",
            Self::Alphanumeric => "letters and digits only",
            Self::Legacy => "letters, digits and symbols !@#$%^&* for older sites",
            Self::Pin => "digits only",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A profile together with a validated length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    profile: Profile,
    length: u32,
}

impl Policy {
    /// `length: None` selects the profile's default length.
    pub fn new(profile: Profile, length: Option<u32>) -> Result<Self, Error> {
        let length = length.unwrap_or_else(|| profile.default_length());
        let range = profile.length_range();
        if !range.contains(&length) {
            return Err(Error::InvalidLength {
                profile,
                length,
                min: *range.start(),
                max: *range.end(),
            });
        }
        Ok(Self { profile, length })
    }

    #[must_use]
    pub const fn profile(self) -> Profile {
        self.profile
    }

    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }
}

impl Default for Policy {
    fn default() -> Self {
        let profile = Profile::Standard;
        Self {
            profile,
            length: profile.default_length(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabets_match_spec_sizes() {
        let sizes: Vec<usize> = Profile::ALL.iter().map(|p| p.alphabet().len()).collect();
        assert_eq!(sizes, [75, 62, 70, 10]);
        for p in Profile::ALL {
            let mut chars: Vec<char> = p.alphabet().chars().collect();
            chars.sort_unstable();
            chars.dedup();
            assert_eq!(chars.len(), p.alphabet().len(), "{p} has duplicates");
        }
    }

    #[test]
    fn lengths_are_validated() {
        assert_eq!(Policy::new(Profile::Pin, None).unwrap().length(), 6);
        assert!(Policy::new(Profile::Pin, Some(4)).is_ok());
        assert!(Policy::new(Profile::Standard, Some(7)).is_err());
        assert!(Policy::new(Profile::Standard, Some(65)).is_err());
    }

    #[test]
    fn names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::from_name(&p.name().to_uppercase()).unwrap(), p);
        }
        assert!(Profile::from_name("strong").is_err());
    }
}
