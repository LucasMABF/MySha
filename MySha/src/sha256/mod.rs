//! Module for hashing with [sha256 algorithm]
//! 
//! This module provides a sha256 implementations through the [sha256()] function, that returns the hash hex wrapped in the [Hash256] type.
//! 
//! # Examples
//! ```
//! use mysha::sha256::{HashError, InputType, sha256, Hash256};
//! # fn main() -> Result<(), HashError>{
//! let hash = sha256("abc", InputType::Text)?;
//! 
//! assert_eq!(hash.get_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
//! 
//! # Ok(())
//! # }
//! ```
//! 
//! **Warning** : the hashing algorithm isn't optimized in the most efficient and fast way.
//! 
//! [sha256 algorithm]: https://en.wikipedia.org/wiki/SHA-2


use std::{fmt, fs::File, io::Read};
use num_bigint::{BigUint, BigInt};

mod helper_functions;
use helper_functions::*;
use num_traits::Num;

/// Enum used to define the input type provided to the [sha256()] function.
pub enum InputType{
    /// Treats the input as an utf-8 text
    Text,
    /// Treats the input as a binary value
    Binary,
    /// treats the input as a little endian binary value, inverse byte order
    LeBinary,
    /// Treats the input as a file
    File,
    /// Treats the input as a hexadecimal value
    Hex,
    /// treats the input as a little endian hexadecimal value, inverse byte order
    LeHex,
    /// Treats the input as a decimal value.
    Decimal,
}

/// The return type of the hashing process
/// 
/// To create a Hash256, refer to the [from_hex][Hash256::from_hex()] method.
# [derive(Debug, Clone, PartialEq)]
pub struct Hash256(String);

impl fmt::Display for Hash256{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        write!(f, "{}", self.0)
    }
}

impl From<&Hash256> for BigInt{
    fn from(value: &Hash256) -> Self {
        BigInt::from_str_radix(&value.0, 16).unwrap()
    }
}

impl From<&Hash256> for BigUint{
    fn from(value: &Hash256) -> Self {
        BigUint::from_str_radix(&value.0, 16).unwrap()
    }
}

impl From<Hash256> for BigInt{
    fn from(value: Hash256) -> Self {
        BigInt::from_str_radix(&value.0, 16).unwrap()
    }
}

impl From<Hash256> for BigUint{
    fn from(value: Hash256) -> Self {
        BigUint::from_str_radix(&value.0, 16).unwrap()
    }
}

impl Hash256{

    /// Creates a [hash type][Hash256] from a hex value.
    /// 
    /// It can be used with little endian values as well, by setting the le parameter to true.
    /// 
    /// # Examples
    /// 
    /// ```
    /// # use mysha::sha256::*;
    /// 
    /// # fn main() -> Result<(), HashError>{
    /// let hash = Hash256::from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", false)?;
    /// 
    /// assert_eq!(hash, sha256("hello", InputType::Text)?, "Error, hashes don't match");
    /// println!("hashes match!");
    /// 
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// If the hash is invalid the function will return a [HashError].
    /// A hash is invalid if it doesn't have the correct number of digits, or if the digits aren't valid as hexadecimal.
    /// 
    /// ```should_panic
    /// # use mysha::sha256::*;
    /// 
    /// # fn main() -> Result<(), HashError>{
    /// let x = Hash256::from_hex("abc", false)?;
    /// 
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex(hex: &str, le: bool) -> Result<Hash256, HashError>{
        if hex.len() != 64{
            Err(HashError::InvalidHash)
        }else{
            let valid = "0123456789abcdef";
            for i in hex.chars(){
                if ! valid.contains(i){
                    return Err(HashError::InvalidHash);
                }
            }
            if le{
               let hex: String = (0..hex.len()).step_by(2).rev().map(|i|&hex[i..i+2]).collect();
               Ok(Hash256(hex))
            }else{
                Ok(Hash256(hex.to_owned()))
            }
            
        }
    }

    /// Returns the hex digest of the hash.
    pub fn get_hex(&self) -> &str{
        &self.0
    }

    /// Returns the hex digest of the hash in little endian byte order.
    pub fn get_hex_le(&self) -> String{
        let le_hex = self.get_hex();
        let le_hex: String = (0..le_hex.len()).step_by(2).rev().map(|i|&le_hex[i..i+2]).collect();
        le_hex
    }
}

/// The error type implemented for this module, with all possible hashing errors.
#[derive(Debug)]
pub enum HashError{
    /// Happens when the type chosen is decimal and it is to big to parse to i128.
    /// This can be fixed by converting the value to be hashed to hex, and using the hex type.
    DecimalTooBig,
    /// Happens when the number provided can't be interpreted as a binary number.
    InvalidBinary,
    /// Happens when the number provided can't be interpreted as a hexadecimal number.
    InvalidHex,
    /// Happens when the number provided can't be interpreted as a decimal number.
    InvalidDecimal,
    /// Can happen for various reasons, like error opening file, reading file, etc.
    ErrorWithFile,
    /// Happens when the input type should be in little endian, but the input doesn't have a whole number of bytes.
    NotWholeBytes,
    /// Happens when trying to convert an invalid hex value to a hash.
    InvalidHash,
}

impl fmt::Display for HashError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        match self {
            HashError::DecimalTooBig => write!(f, "Decimal Too big for i128."),
            HashError::InvalidBinary => write!(f, "Invalid value for binary."),
            HashError::InvalidHex => write!(f, "Invalid value for hex."),
            HashError::InvalidDecimal => write!(f, "Invalid value for decimal."),
            HashError::ErrorWithFile => write!(f, "Error while handling file."),
            HashError::NotWholeBytes => write!(f, "You can't use little endian if you don't provide a whole number of bytes"),
            HashError::InvalidHash => write!(f, "Invalid hex for a hash."),
        }
    }
}

/// The hashing function using the [sha256 algorithm]
/// 
/// This function can hash different types of information, that are provided by the [InputType].
/// 
/// # Examples
/// ```
/// # use mysha::sha256::*;
/// 
/// # fn main() -> Result<(), HashError>{
/// // hash twice
/// let hash1 = sha256("abc", InputType::Text)?;
/// let hash2 = sha256(hash1.get_hex(), InputType::Hex)?;
/// assert_eq!(hash2.get_hex(), "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358");
/// 
/// # Ok(())
/// # }
/// ```
/// 
/// ```no_run
/// // hash file
/// use std::fs::File;
/// use std::io::Write;
/// # use mysha::sha256::*;
/// # fn main() -> Result<(), HashError>{ 
/// let mut file = File::create("abc.txt").unwrap();
/// file.write_all(b"abc").unwrap();
/// 
/// let file_hash = sha256("abc.txt", InputType::File)?;
/// assert_eq!(file_hash.get_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
/// 
/// # Ok(())
/// # }
/// ```
/// 
/// # Errors 
/// This function can return an Error if it receives invalid arguments.
/// The Errors possible are explained in [HashError].
/// 
/// [sha256 algorithm]: https://en.wikipedia.org/wiki/SHA-2
pub fn sha256(message: &str, input_type: InputType) -> Result<Hash256, HashError>{
    let mut bits = match input_type{
        InputType::Binary => {
            binary_handling::validate_bits(message)?;
            message.to_string()
        },
        InputType::LeBinary => {
            binary_handling::validate_bits(message)?;
            if message.len() % 8 != 0{
                return Err(HashError::NotWholeBytes);
            }
            (0..message.len()).step_by(8).rev().map(|i| &message[i..i+8]).collect()
        }
        InputType::Text => binary_handling::get_binary_message(message),
        InputType::Hex => binary_handling::get_bits_hex(message, false)?,
        InputType::LeHex => binary_handling::get_bits_hex(message, true)?,
        InputType::Decimal => format!("{:b}", message.parse::<i128>().map_err(|err|{
            match err.kind(){
                std::num::IntErrorKind::PosOverflow => HashError::DecimalTooBig,
                _ => HashError::InvalidDecimal
            }   
        })?),
        InputType::File => {
            let mut file = File::open(message).map_err(|_| HashError::ErrorWithFile)?;
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|_| HashError::ErrorWithFile)?;
            binary_handling::get_binary_message(&content)
        },
    };

    binary_handling::pad(&mut bits);

    let message_blocks = binary_handling::get_message_blocks(&bits);

    let a = constants::initialize_a();

    let (mut a0, mut b0, mut c0, mut d0, mut e0, mut f0, mut g0, mut h0) = (a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

    let k = constants::initialize_k();


    for block in message_blocks.iter(){
        let mut message_schedule = binary_handling::get_message_schedule(block);

        for i in 16..64{
            message_schedule.push(operations::addn(vec![operations::l_sigma1(message_schedule[i - 2]), message_schedule[i - 7], operations::l_sigma0(message_schedule[i - 15]), message_schedule[i - 16]]));
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (a0, b0, c0, d0, e0, f0, g0, h0);

                
        for (i, m) in message_schedule.iter().enumerate(){
            let t1 = operations::addn(vec![operations::u_sigma1(e), operations::choice(e, f, g), h, k[i], *m]);
            let t2 = operations::add(operations::u_sigma0(a), operations::majority(a, b, c));

            h = g;
            g = f;
            f = e;
            e = operations::add(d, t1);
            d = c;
            c = b;
            b = a;
            a = operations::add(t1, t2);
        }

        a0 = operations::add(a, a0);
        b0 = operations::add(b, b0);
        c0 = operations::add(c, c0);
        d0 = operations::add(d, d0);
        e0 = operations::add(e, e0);
        f0 = operations::add(f, f0);
        g0 = operations::add(g, g0);
        h0 = operations::add(h, h0);
    }

    let hash256 = format!("{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", a0, b0, c0, d0, e0, f0, g0, h0);
    return Ok(Hash256(hash256));
}
