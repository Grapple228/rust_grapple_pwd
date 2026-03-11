//! The pwd lib is responsible for hashing and validating hashes.
//! It follows a multi-scheme hashing code design, allowing each
//! scheme to provide its own hashing and validation methods.

// region:    --- Modules

mod config;
mod error;
mod scheme;

pub use self::error::{Error, Result};
use bytes::Bytes;
pub use config::hash_config;
pub use scheme::SchemeStatus;

use crate::scheme::get_scheme;
use lazy_regex::regex_captures;
use scheme::Scheme;
use std::{borrow::Cow, str::FromStr};
use uuid::Uuid;

// endregion: --- Modules

// region:    --- Types

/// The clean content to hash, with the salt.
#[cfg_attr(test, derive(Clone))]
pub struct ContentToHash {
    pub content: Bytes,
    pub salt: Option<Uuid>,
}

impl ContentToHash {
    pub fn with_random_salt(content: impl Into<Bytes>) -> Self {
        Self {
            content: content.into(),
            salt: Some(Uuid::new_v4()),
        }
    }
}

// endregion: --- Types

/// Main Hasher struct
#[derive(Clone, Debug)]
pub struct Hasher {
    scheme_name: String,
    key_id: String,
}

impl Hasher {
    pub fn new(scheme_name: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            scheme_name: scheme_name.into(),
            key_id: key_id.into(),
        }
    }

    pub fn with_default_scheme(key_id: impl Into<String>) -> Result<Self> {
        if let Some(scheme_name) = &hash_config().hash_scheme {
            Ok(Self::new(scheme_name, key_id))
        } else {
            Err(Error::DefaultSchemeNotSet)
        }
    }

    pub fn requires_salt(&self) -> Result<bool> {
        Ok(get_scheme(&self.scheme_name)?.requires_salt())
    }

    /// Hash the content with the configured scheme
    pub async fn hash(&self, to_hash: ContentToHash) -> Result<String> {
        let scheme_name = self.scheme_name.clone();
        let key_id = self.key_id.clone();

        tokio::task::spawn_blocking(move || Self::hash_for_scheme(&scheme_name, &key_id, to_hash))
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

    pub fn scheme_name(&self) -> &str {
        &self.scheme_name
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn hash_for_scheme(scheme_name: &str, key_id: &str, to_hash: ContentToHash) -> Result<String> {
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

pub fn is_salt_required() -> Result<bool> {
    Hasher::with_default_scheme("default")?.requires_salt()
}

pub async fn hash_content(key_id: &str, to_hash: ContentToHash) -> Result<String> {
    Hasher::with_default_scheme(key_id)?.hash(to_hash).await
}

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
    scheme_name: String,
    hashed: String,
}

impl FromStr for ContentParts {
    type Err = Error;

    fn from_str(pwd_with_scheme: &str) -> Result<Self> {
        regex_captures!(r#"^#(\w+)#(.*)"#, pwd_with_scheme)
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
    use std::borrow::Cow;

    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn test_hasher_struct() -> Result<()> {
        // -- Setup & Fixtures
        let fx_salt = Uuid::parse_str("f05e8961-d6ad-4086-9e78-a6de065e5453")?;
        let fx_to_hash = ContentToHash {
            content: "hello world".into(),
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
        let fx_to_hash = ContentToHash::with_random_salt("test content"); // ✅ байты!

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
