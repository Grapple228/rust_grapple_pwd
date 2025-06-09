//! Tmp scheme for tests only

use super::ContentToHash;
use super::{Result, Scheme};

pub struct SchemeTmp;

impl Scheme for SchemeTmp {
    fn hash(&self, _to_hash: &ContentToHash) -> Result<String> {
        Ok(String::from("tmp_hash"))
    }

    fn validate(&self, _to_hash: &ContentToHash, _pwd_ref: &str) -> Result<()> {
        Ok(())
    }
}
