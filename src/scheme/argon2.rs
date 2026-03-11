use super::{Error, Result, Scheme};
use crate::{hash_config, ContentToHash};
use argon2::password_hash::SaltString;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher as _, PasswordVerifier as _, Version,
};
use std::collections::HashMap;
use std::sync::OnceLock;

pub struct SchemeArgon2id;

impl Scheme for SchemeArgon2id {
    fn hash(&self, key_id: &str, to_hash: &ContentToHash) -> Result<String> {
        let salt = to_hash.salt.ok_or_else(|| Error::Salt)?;
        let argon2 = get_argon2(key_id).ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        let salt_b64 = SaltString::encode_b64(salt.as_bytes()).map_err(|_| Error::Salt)?;

        let content = argon2
            .hash_password(&to_hash.content, &salt_b64)
            .map_err(|_| Error::Hash)?
            .to_string();

        Ok(content)
    }

    fn validate(&self, key_id: &str, to_hash: &ContentToHash, pwd_ref: &str) -> Result<()> {
        let argon2 = get_argon2(key_id).ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        let parsed_hash_ref = PasswordHash::new(pwd_ref).map_err(|_| Error::Hash)?;

        argon2
            .verify_password(&to_hash.content, &parsed_hash_ref)
            .map_err(|_| Error::PwdValidate)
    }

    fn requires_salt(&self) -> bool {
        false
    }
}

pub fn get_argon2(key_id: &str) -> Option<&'static Argon2<'static>> {
    static INSTANCE: OnceLock<HashMap<String, Argon2<'static>>> = OnceLock::new();

    let argons = INSTANCE.get_or_init(|| {
        let mut keys = HashMap::new();
        for (id, key) in &hash_config().keys {
            let argon = Argon2::new_with_secret(
                key.as_slice(), // ✅ key уже Vec<u8> из конфига
                Algorithm::Argon2id,
                Version::V0x13,
                Params::default(),
            )
            .expect("Unable to init argon2");

            keys.insert(id.clone(), argon);
        }
        keys
    });

    argons.get(key_id)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_argon2id_hash_into_b64u_ok() -> Result<()> {
        let fx_to_hash = ContentToHash {
            content: "hello world".into(), // ✅ байты!
            salt: Some(Uuid::parse_str("f05e8961-d6ad-4086-9e78-a6de065e5453").unwrap()),
        };
        let fx_res = "$argon2id$v=19$m=19456,t=2,p=1$8F6JYdatQIaeeKbeBl5UUw$eScofyc3Gazk0ZLtbZnNo+mrBNKJdmqOXZCf4zDDU4Y";

        let scheme = SchemeArgon2id;
        let res = scheme.hash("pwd", &fx_to_hash)?;

        assert_eq!(res, fx_res);
        Ok(())
    }
}
