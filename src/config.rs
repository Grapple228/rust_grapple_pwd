//! Crate config

use grapple_utils::envs::{get, get_keys_b64u_as_u8s};

use std::{collections::HashMap, sync::OnceLock};

pub fn hash_config() -> &'static HashConfig {
    static INSTANCE: OnceLock<HashConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        HashConfig::load_from_env()
            .unwrap_or_else(|ex| panic!("FATAL - WHOLE LOADING CONF - Cause: {ex:?}"))
    })
}

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct HashConfig {
    /// The scheme to use for content hashing.
    pub hash_scheme: Option<String>,
    /// The keys to use for content hashing in Base64Url format.
    pub keys: HashMap<String, Vec<u8>>,
}

impl HashConfig {
    fn load_from_env() -> grapple_utils::envs::Result<HashConfig> {
        Ok(HashConfig {
            hash_scheme: get("HASHER_DEFAULT_SCHEME")
                .map(|v| Some(v))
                .unwrap_or_default(),
            keys: get_keys_b64u_as_u8s("HASHER_KEYS")?,
        })
    }
}
