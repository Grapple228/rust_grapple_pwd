// region:    --- Modules

mod argon2;
mod error;
mod sha256;
#[cfg(test)]
mod tmp;

pub use self::error::{Error, Result};

use enum_dispatch::enum_dispatch;

use super::ContentToHash;

// endregion: --- Modules

#[derive(Debug)]
pub enum SchemeStatus {
    Ok,       // The pwd uses the latest scheme. All good.
    Outdated, // The pwd uses an old scheme.
}

#[enum_dispatch]
pub trait Scheme {
    fn hash(&self, key_id: &str, to_hash: &ContentToHash) -> Result<String>;

    fn validate(&self, key_id: &str, to_hash: &ContentToHash, content_ref: &str) -> Result<()>;

    fn requires_salt(&self) -> bool {
        true
    }
}

#[enum_dispatch(Scheme)]
pub enum SchemeDispatcher {
    Argon2id(argon2::SchemeArgon2id),
    Sha256(sha256::SchemeHmacSha256),
    #[cfg(test)]
    Tmp(tmp::SchemeTmp),
}

pub fn get_scheme(scheme_name: &str) -> Result<impl Scheme> {
    match scheme_name {
        "argon2id" => Ok(SchemeDispatcher::Argon2id(argon2::SchemeArgon2id)),
        "hmac_sha256" => Ok(SchemeDispatcher::Sha256(sha256::SchemeHmacSha256)),
        #[cfg(test)]
        "tmp" => Ok(SchemeDispatcher::Tmp(tmp::SchemeTmp)),
        _ => Err(Error::SchemeNotFound(scheme_name.to_string())),
    }
}
