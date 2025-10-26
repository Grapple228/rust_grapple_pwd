use super::{Error, Result, Scheme};
use crate::{hash_config, ContentToHash};
use grapple_utils::b64;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::OnceLock;

pub struct SchemeHmacSha256;

impl Scheme for SchemeHmacSha256 {
    fn hash(&self, key_id: &str, to_hash: &ContentToHash) -> Result<String> {
        let key = get_hmac_key(key_id).ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Hash)?;

        mac.update(to_hash.content.as_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        Ok(b64::encode(code_bytes))
    }

    fn validate(&self, key_id: &str, to_hash: &ContentToHash, pwd_ref: &str) -> Result<()> {
        let computed_hash = self.hash(key_id, to_hash)?;

        // Сравнение с постоянным временем для защиты от timing attacks
        if constant_time_eq::constant_time_eq(computed_hash.as_bytes(), pwd_ref.as_bytes()) {
            Ok(())
        } else {
            Err(Error::PwdValidate)
        }
    }

    /// HMAC не требует хранения соли отдельно, так как ключ уже действует как соль
    fn requires_salt(&self) -> bool {
        false
    }
}

/// Получить HMAC ключ для указанного key_id
pub fn get_hmac_key(key_id: &str) -> Option<&'static [u8]> {
    static INSTANCE: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();

    let keys = INSTANCE.get_or_init(|| {
        let mut key_map = HashMap::new();

        for (id, key_bytes) in &hash_config().keys {
            key_map.insert(id.clone(), key_bytes.clone());
        }

        key_map
    });

    keys.get(key_id).map(|vec| vec.as_slice())
}

// region:    --- Tests
#[cfg(test)]
mod tests {
    pub type Result<T> = core::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For tests.

    use super::*;
    use uuid::Uuid;
    use ContentToHash;

    #[test]
    fn test_sha256_hash_into_b64u_ok() -> Result<()> {
        // -- Setup & Fixtures
        let fx_to_hash = ContentToHash {
            content: "hello world".to_string(),
            salt: Some(Uuid::parse_str("f05e8961-d6ad-4086-9e78-a6de065e5453")?),
        };
        // Ожидаемый HMAC-SHA256 хеш для "hello world" с ключом "pwd"
        let fx_res = "8E0N9GTmqE/1dYYzRXlMsPsK8I0J0O+X6kal2p3bgzQ";

        // -- Exec
        let scheme = SchemeHmacSha256;
        let res = scheme.hash("pwd", &fx_to_hash)?;

        // -- Check
        assert_eq!(res, fx_res);

        Ok(())
    }
}
// endregion: --- Tests
