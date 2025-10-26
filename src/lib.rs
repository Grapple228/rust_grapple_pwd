//! The pwd lib is responsible for hashing and validating hashes.
//! It follows a multi-scheme hashing code design, allowing each
//! scheme to provide its own hashing and validation methods.
//!
//! Code Design Points:
//!
//! - Exposes two public async functions `hash_pwd(...)` and `validate_pwd(...)`
//! - `ContentToHash` represents the data to be hashed along with the corresponding salt.
//! - `SchemeStatus` is the result of `validate_pwd` which, upon successful validation, indicates
//!   whether the password needs to be re-hashed to adopt the latest scheme.
//! - Internally, the `pwd` lib implements a multi-scheme code design with the `Scheme` trait.
//! - The `Scheme` trait exposes sync functions `hash` and `validate` to be implemented for each scheme.
//! - The two public async functions `hash_pwd(...)` and `validate_pwd(...)` call the scheme using
//!   `spawn_blocking` to ensure that long hashing/validation processes do not hinder the execution of smaller tasks.
//! - Schemes are designed to be agnostic of whether they are in an async or sync context, hence they are async-free.

// region:    --- Modules

// -- Modules

mod config;
mod error;
mod scheme;

// -- Flatten
pub use self::error::{Error, Result};
pub use config::hash_config;
pub use scheme::SchemeStatus;

use crate::scheme::get_scheme;
use lazy_regex::regex_captures;
use scheme::Scheme;
use std::str::FromStr;
use uuid::Uuid;

// endregion: --- Modules

// region:    --- Types

/// The clean content to hash, with the salt.
///
/// Notes:
///    - Since content is sensitive information, we do NOT implement default debug for this struct.
///    - The clone is only implement for testing
#[cfg_attr(test, derive(Clone))]
pub struct ContentToHash {
    pub content: String, // Clear content.
    pub salt: Option<Uuid>,
}

impl ContentToHash {
    pub fn with_random_salt(content: impl Into<String>) -> Self {
        ContentToHash {
            content: content.into(),
            salt: Some(Uuid::new_v4()),
        }
    }
}

// endregion: --- Types

/// Main Hasher struct that provides hashing and validation functionality
/// for different schemes (Argon2id, HMAC, etc.)
#[derive(Clone, Debug)]
pub struct Hasher {
    scheme_name: String,
    key_id: String,
}

impl Hasher {
    /// Create a new Hasher with the specified scheme and key_id
    pub fn new(scheme_name: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            scheme_name: scheme_name.into(),
            key_id: key_id.into(),
        }
    }

    /// Create a Hasher with the default scheme from config
    pub fn with_default_scheme(key_id: impl Into<String>) -> Result<Self> {
        if let Some(scheme_name) = &hash_config().hash_scheme {
            Ok(Self::new(scheme_name, key_id))
        } else {
            Err(Error::DefaultSchemeNotSet)
        }
    }

    /// Returns true if the current scheme requires salt
    pub fn requires_salt(&self) -> Result<bool> {
        Ok(get_scheme(&self.scheme_name)?.requires_salt())
    }

    /// Hash the content with the configured scheme
    pub async fn hash(&self, to_hash: ContentToHash) -> Result<String> {
        let scheme_name = self.scheme_name.clone();
        let key_id = self.key_id.clone();

        tokio::task::spawn_blocking(move || Self::hash_for_scheme(&scheme_name, &key_id, &to_hash))
            .await
            .map_err(|_| Error::FailSpawnBlockForHash)?
    }

    /// Validate if content matches the reference hash
    pub async fn validate(
        &self,
        to_hash: ContentToHash,
        content_ref: &str,
    ) -> Result<SchemeStatus> {
        let ContentParts {
            scheme_name,
            hashed,
        } = content_ref.parse()?;

        // Check if scheme is up-to-date
        let scheme_status = if &scheme_name == &self.scheme_name {
            SchemeStatus::Ok
        } else {
            SchemeStatus::Outdated
        };

        let key_id = self.key_id.clone();

        tokio::task::spawn_blocking(move || {
            Self::validate_for_scheme(&scheme_name, &key_id, to_hash, hashed)
        })
        .await
        .map_err(|_| Error::FailSpawnBlockForValidate)??;

        Ok(scheme_status)
    }

    /// Get the current scheme name
    pub fn scheme_name(&self) -> &str {
        &self.scheme_name
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    // Private helper functions
    fn hash_for_scheme(scheme_name: &str, key_id: &str, to_hash: &ContentToHash) -> Result<String> {
        let content_hashed = get_scheme(scheme_name)?.hash(key_id, &to_hash)?;
        Ok(format!("#{scheme_name}#{content_hashed}"))
    }

    fn validate_for_scheme(
        scheme_name: &str,
        key_id: &str,
        to_hash: ContentToHash,
        content_ref: String,
    ) -> Result<()> {
        get_scheme(scheme_name)?.validate(key_id, &to_hash, &content_ref)?;
        Ok(())
    }
}

// region:    --- Public Functions

// Convenience functions for backward compatibility
/// Returns true if need to store salt somewhere to decode the hash.
pub fn is_salt_required() -> Result<bool> {
    Hasher::with_default_scheme("default")?.requires_salt()
}

/// Hash the content with the default scheme.
pub async fn hash_content(key_id: &str, to_hash: ContentToHash) -> Result<String> {
    Hasher::with_default_scheme(key_id)?.hash(to_hash).await
}

/// Validate if an ContentToHash matches.
pub async fn validate_content(
    key_id: &str,
    to_hash: ContentToHash,
    content_ref: &str,
) -> Result<SchemeStatus> {
    Hasher::with_default_scheme(key_id)?
        .validate(to_hash, content_ref)
        .await
}

struct ContentParts {
    /// The scheme only (e.g., "argon2id")
    scheme_name: String,
    /// The hashed password,
    hashed: String,
}

impl FromStr for ContentParts {
    type Err = Error;

    fn from_str(pwd_with_scheme: &str) -> Result<Self> {
        regex_captures!(
            r#"^#(\w+)#(.*)"#, // a literal regex
            pwd_with_scheme
        )
        .map(|(_, scheme, hashed)| Self {
            scheme_name: scheme.to_string(),
            hashed: hashed.to_string(),
        })
        .ok_or(Error::PwdWithSchemeFailedParse)
    }
}

// endregion: --- Privates

// region:    --- Tests
#[cfg(test)]
mod tests {
    use super::*;

    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn test_hasher_struct() -> Result<()> {
        // -- Setup & Fixtures
        let fx_salt = Uuid::parse_str("f05e8961-d6ad-4086-9e78-a6de065e5453")?;
        let fx_to_hash = ContentToHash {
            content: "hello world".to_string(),
            salt: Some(fx_salt),
        };

        // -- Exec with Hasher struct
        let hasher = Hasher::new("tmp", "pwd");
        let content_hashed = hasher.hash(fx_to_hash.clone()).await?;
        let content_validate = hasher.validate(fx_to_hash, &content_hashed).await?;

        // -- Check
        assert!(
            matches!(content_validate, SchemeStatus::Ok),
            "status should be SchemeStatus::Ok"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_hasher_different_schemes() -> Result<()> {
        let fx_to_hash = ContentToHash::with_random_salt("test content");

        // Test with different schemes
        let argon_hasher = Hasher::new("argon2id", "pwd");
        let hmac_hasher = Hasher::new("hmac-sha256", "client_secret");

        let argon_hash = argon_hasher.hash(fx_to_hash.clone()).await?;
        let hmac_hash = hmac_hasher.hash(fx_to_hash.clone()).await?;

        // Both should hash successfully but produce different results
        assert!(argon_hash.starts_with("#argon2id#"));
        assert!(hmac_hash.starts_with("#hmac-sha256#"));
        assert_ne!(argon_hash, hmac_hash);

        Ok(())
    }
}
// endregion: --- Tests
