//! Shared username and set display-name validation.

use once_cell::sync::Lazy;
use regex::Regex;
use thiserror::Error;

pub const DEFAULT_SET_NAME: &str = "default";

static USERNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("username regex"));
static SET_NAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9 _-]{1,64}$").expect("set name regex"));

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UsernameError {
    #[error("Username and password required.")]
    Empty,
    #[error("Username may only include letters, numbers, '_' or '-'")]
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SetNameError {
    #[error("invalid set name")]
    Invalid,
}

pub fn normalise_username(username: &str) -> Result<String, UsernameError> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err(UsernameError::Empty);
    }
    if !USERNAME_RE.is_match(trimmed) {
        return Err(UsernameError::Invalid);
    }
    Ok(trimmed.to_string())
}

pub fn normalise_set_name(set_name: Option<&str>) -> Result<String, SetNameError> {
    normalise_set_name_inner(set_name.unwrap_or(DEFAULT_SET_NAME), true)
}

pub fn normalise_custom_set_name(set_name: &str) -> Result<String, SetNameError> {
    normalise_set_name_inner(set_name, false)
}

fn normalise_set_name_inner(set_name: &str, allow_default: bool) -> Result<String, SetNameError> {
    let trimmed = set_name.trim();
    let candidate = if trimmed.is_empty() {
        if allow_default {
            DEFAULT_SET_NAME.to_string()
        } else {
            return Err(SetNameError::Invalid);
        }
    } else {
        trimmed.to_string()
    };

    if (!allow_default && candidate == DEFAULT_SET_NAME)
        || candidate == "."
        || candidate == ".."
        || !SET_NAME_RE.is_match(&candidate)
    {
        return Err(SetNameError::Invalid);
    }

    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_name_trims_and_defaults() {
        assert_eq!(normalise_set_name(Some("  work  ")).unwrap(), "work");
        assert_eq!(normalise_set_name(None).unwrap(), "default");
        assert_eq!(normalise_set_name(Some("   ")).unwrap(), "default");
    }

    #[test]
    fn custom_set_name_rejects_default_and_blank() {
        assert_eq!(
            normalise_custom_set_name("default").unwrap_err(),
            SetNameError::Invalid
        );
        assert_eq!(
            normalise_custom_set_name("  default  ").unwrap_err(),
            SetNameError::Invalid
        );
        assert_eq!(
            normalise_custom_set_name("").unwrap_err(),
            SetNameError::Invalid
        );
    }

    #[test]
    fn set_name_accepts_limits_and_rejects_dot_segments() {
        let sixty_four = "a".repeat(64);
        assert_eq!(normalise_set_name(Some(&sixty_four)).unwrap(), sixty_four);
        assert!(normalise_set_name(Some(&"a".repeat(65))).is_err());
        for raw in [".", "..", "a/b", "name!"] {
            assert_eq!(
                normalise_set_name(Some(raw)).unwrap_err(),
                SetNameError::Invalid,
                "for {raw:?}"
            );
        }
    }

    #[test]
    fn username_empty_and_invalid_stay_distinct() {
        assert_eq!(
            normalise_username("  alice-1_2  ").unwrap(),
            "alice-1_2"
        );
        assert_eq!(normalise_username("   ").unwrap_err(), UsernameError::Empty);
        assert_eq!(
            normalise_username("bad name!").unwrap_err(),
            UsernameError::Invalid
        );
        assert_eq!(
            UsernameError::Empty.to_string(),
            "Username and password required."
        );
        assert_eq!(
            UsernameError::Invalid.to_string(),
            "Username may only include letters, numbers, '_' or '-'"
        );
    }
}
