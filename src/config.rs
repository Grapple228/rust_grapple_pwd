//! Crate config

use grapple_utils::envs::{get_env, get_env_b64u_as_u8s};

use std::sync::OnceLock;

pub fn pwd_config() -> &'static PwdConfig {
    static INSTANCE: OnceLock<PwdConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        PwdConfig::load_from_env()
            .unwrap_or_else(|ex| panic!("FATAL - WHOLE LOADING CONF - Cause: {ex:?}"))
    })
}

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct PwdConfig {
    // -- Pwd
    /// The scheme to use for password hashing.
    pub pwd_scheme: String,
    /// The key to use for password hashing in Base64Url format.
    pub pwd_key: Vec<u8>,
}

impl PwdConfig {
    fn load_from_env() -> grapple_utils::envs::Result<PwdConfig> {
        Ok(PwdConfig {
            pwd_scheme: get_env("PWD_SCHEME")?,
            pwd_key: get_env_b64u_as_u8s("PWD_KEY")?,
        })
    }
}
