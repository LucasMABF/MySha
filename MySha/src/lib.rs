//! A library crate that provides different cryptography tools and algorithms. 
//! 
//! This is the library part of the [cli tool] binary crate.
//! 
//! Every different cryptography concept, tool or algorithm is located in a different module, 
//! so browse the modules to see what is provided.
//! 
//! [cli tool]: https://github.com/lucasmabf/mysha

use core::fmt;

use ecc::EccError;
use sha256::HashError;

pub mod ecc;
pub mod sha256;

/// Error type for this library
/// 
/// This type allows functions to return Errors of different modules of this library.
/// 
/// # Examples
/// 
/// ```
/// use mysha::{sha256::{sha256, InputType}, ecc::*, MyshaError};
/// 
/// fn keypair_from_hash(message: &str) -> Result<KeyPair, MyshaError>{
///     let hash = sha256(message, InputType::Text)?;
///     let curve = Curve::secp256k1();
///     let kp = KeyPair::new(hash, curve)?;
/// 
///     Ok(kp)
/// }
/// ```
#[derive(Debug)]
pub enum MyshaError{
    Ecc(EccError),
    Hash(HashError),
}

impl fmt::Display for MyshaError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self{
            &MyshaError::Ecc(e) => write!(f, "{}", e),
            &MyshaError::Hash(e) => write!(f, "{}", e),
        }
    }
}

impl From<EccError> for MyshaError{
    fn from(value: EccError) -> Self {
        MyshaError::Ecc(value)
    }
}

impl From<HashError> for MyshaError{
    fn from(value: HashError) -> Self {
        MyshaError::Hash(value)
    }
}