//! Module for performing [elliptic curve cryptography][ecc] operations.
//! 
//! This module provides tools for dealing with [asymetric cryptography] over [elliptic curves];
//! 
//! It provides types and methods that enable you to use ecc, such as creating [private keys][PrivKey], [public keys][PubKey],
//! [signing][PrivKey::sign], and performing ecc math, such as point [doubling][Curve::double], [adding][Curve::add] and [multiplying][Curve::multiply].
//! 
//! # Examples
//! - Simple generating key-pair and signing:
//! ```
//! use mysha::ecc::*;
//! use mysha::sha256::{sha256, InputType};
//! use rand::{self, SeedableRng};
//! use num_bigint::{RandBigInt, BigUint};
//! 
//! let curve = Curve::secp256k1();
//! 
//! let mut rng = rand::rngs::StdRng::from_entropy(); // check if your rng is cryptographically secure
//! 
//! let private_key = rng.gen_biguint_range(&BigUint::from(1_u8), curve.get_n()); // needs to be BigInt, this makes code more complex
//! 
//! let key_pair = KeyPair::new(private_key, curve).unwrap();
//! 
//! let signature = key_pair.sign("this message needs to be hashed and signed", InputType::Text).unwrap();
//! 
//! println!("{:?}", signature); 
//! 
//! assert!(signature.verify("this message needs to be hashed and signed", InputType::Text).unwrap());
//! ```
//! 
//! [ecc]: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
//! [asymetric cryptography]: https://en.wikipedia.org/wiki/Public-key_cryptography
//! [elliptic curves]: https://en.wikipedia.org/wiki/Elliptic_curve

use num_bigint::{BigUint, ToBigInt, RandBigInt, BigInt};
use rand::{self, SeedableRng};

mod ecc_math;

pub use ecc_math::{Curve, EccError, Point};

use crate::{sha256::{sha256, InputType}, MyshaError};

use self::ecc_math::{get_mod, mod_inv};


/// Key Pair type 
/// 
/// KeyPair contains both private and public keys and the curve they are on.
/// 
/// To create a KeyPair, refer to the [new][KeyPair::new] and [from_private][KeyPair::from_private] methods.
/// Since the fields are private, these methods are the only way to create a KeyPair.
/// This ensures that the KeyPair type always holds valid values.
#[derive(Debug)]
pub struct KeyPair{
    private: BigUint,
    public: Point,
    curve: Curve,
}

impl KeyPair{
    /// Creates a new [KeyPair] from a number as the private key, and a [Curve]
    /// 
    /// It can be called on any type that can be converted into a [BigUint], so it needs to be unsigned and an integer. You can also use [BigUint] itself for bigger numbers.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// # fn main() -> Result<(), EccError>{
    /// let key_pair = KeyPair::new(10_u8, Curve::secp256k1())?; // not a very good private key though
    /// 
    /// println!("{:?}", key_pair);
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// 
    /// This can fail when the number provided isn't a valid private key, 
    /// or when the curve is [problematic], that is, not suitable for ecc.
    /// 
    /// [problematic]: Curve#problematic-curves
    pub fn new<T: Into<BigInt> + Into<BigUint>>(private: T, curve: Curve) -> Result<KeyPair, EccError>{
        let private: BigUint = private.into();
        if private == BigUint::from(0_u8) || &private >= curve.get_n(){
            return Err(EccError::InvalidPrivateKey);
        }
        let public = curve.multiply(curve.get_g(), private.to_bigint().unwrap())?;
        Ok(KeyPair{
            private,
            public,
            curve
        })
    }

    /// Creates a new [KeyPair] from a [PrivKey]
    /// 
    /// # Errors
    /// 
    /// This can fail and produce an error only when the curve is [problematic].
    /// Since the private key needs to be valid to Create a [PrivKey] type.
    /// 
    /// [problematic]: Curve#problematic-curves
    pub fn from_private(private: &PrivKey) -> Result<KeyPair, EccError>{
        let public = private.curve.multiply(private.curve.get_g(), private.private.to_bigint().unwrap())?;
        Ok(KeyPair{
            private: private.private.clone(),
            public,
            curve: private.curve.clone(),
        })
    }

    /// Returns the [Curve] used to get the [KeyPair].
    pub fn get_curve(&self) -> &Curve{
        &self.curve
    }
    
    /// Returns the private key.
    pub fn get_private(&self) -> &BigUint{
        &self.private
    }

    /// Returns the public key.
    pub fn get_public(&self) -> &Point{
        &self.public
    }

    /// Creates a [PrivKey] type from a [KeyPair].
    pub fn private(&self) -> PrivKey{
        PrivKey{
            private: self.private.clone(),
            curve: self.curve.clone(),
        }
    }

    /// Creates a [PubKey] type from a [KeyPair].
    pub fn public(&self) -> PubKey{
        PubKey {
            public: self.public.clone(),
            curve: self.curve.clone(),
        }
    }

    /// Signs a message using the [KeyPair].
    /// 
    /// Creates a [Signature] for a message.
    /// 
    /// The message and its type needs to be provided, the type is informed through the [InputType], that is used in the [sha256][crate::sha256] module.
    /// That's because the message needs to be hashed, and the hash is signed with the public key.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::{MyshaError, ecc::*};
    /// use mysha::sha256::InputType;
    /// 
    /// # fn main() -> Result<(), MyshaError>{
    /// let key_pair = KeyPair::new(1001001_u32, Curve::secp256k1())?;
    /// let sig = key_pair.sign("73", InputType::Decimal)?;
    /// 
    /// println!("{:?}", sig);
    /// 
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// 
    /// This can only emit an [error][EccError] if there is something [wrong] with the curve.
    /// Or if there is a [hashing problem][crate::sha256::HashError].
    /// 
    /// [wrong]: Curve#problematic-curves
    pub fn sign(&self, message: &str, input_type: InputType) -> Result<Signature, MyshaError>{
        let hash = sha256(message, input_type)?;
        let mut rng = rand::rngs::StdRng::from_entropy();
        let curve = self.get_curve();
        let n = curve.get_n().to_bigint().unwrap();
        let random_nonce = rng.gen_bigint_range(&BigInt::from(1_u8), &n);
        
        let r = get_mod(&curve.multiply(curve.get_g(), random_nonce.clone())?.get_x().unwrap().to_bigint().unwrap(), &n)?;
        let s = get_mod(&(mod_inv(&random_nonce, &n)? * (BigInt::from(&hash) + self.get_private().to_bigint().unwrap() * &r)), &n)?;

        Ok(Signature{
            r: r.to_biguint().unwrap(),
            s: s.to_biguint().unwrap(),
            curve: curve.clone(),
            public: self.get_public().clone(),
        })
    }
}

/// Public Key type
/// 
/// PubKey contains only the public key and the curve it is on.
/// 
/// To create a PubKey, refer to the [new][PubKey::new()] method,
/// since its fields are private to ensure that it is a valid public key.
#[derive(Debug)]
pub struct PubKey{
    /// Public Key
    public: Point,
    /// Curve the Public key point is on
    curve: Curve,
}

impl PubKey{
    /// Creates a [PubKey] from a [Point] and a [Curve]
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// use num_bigint::BigInt;
    /// 
    /// # fn main() -> Result<(), EccError>{
    /// let curve = Curve::secp256k1();
    /// let point = curve.multiply(curve.get_g(), 73)?;
    /// 
    /// let public_key = PubKey::new(point, curve)?;
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    /// 
    /// This can fail if the [Point] provided can't be a valid public key.
    pub fn new(public: Point, curve: Curve) -> Result<PubKey, EccError>{
        if ! curve.is_on_curve(&public){
            Err(EccError::NotOnCurve)
        }else if public == Point::PointAtInfinity{
            Err(EccError::PublicKeyOnInfinity)
        }else{
            Ok(PubKey{
                public,
                curve,
            })
        }
    }

    /// Returns the public key
    pub fn get_public(&self) -> &Point{
        &self.public
    }

    /// Returns the curve containing the public key
    pub fn get_curve(&self) -> &Curve{
        &self.curve
    }
}


/// Private Key Type 
/// 
/// PrivKey contains only the private key and the curve it refers to.
/// 
/// To create a PrivKey, refer to [new][PrivKey::new()] method,
/// since its field are private, to ensure it is a valid private key.
#[derive(Debug)]
pub struct PrivKey{
    /// Private Key
    private: BigUint,
    /// Curve that Private Key refers to
    curve: Curve,
}

impl PrivKey{
    /// Creates a [PrivKey] from a private number and a [Curve]
    /// 
    /// It can be called on any type that can be converted into a [BigUint], so it needs to be unsigned and an integer.
    /// You can also use [BigUint] itself for bigger numbers.
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// use num_bigint::BigInt;
    /// 
    /// # fn main() -> Result<(), EccError>{
    /// let curve = Curve::secp256k1();
    /// 
    /// let private_key = PrivKey::new(73_u32, curve)?;
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    /// 
    /// This can fail if the number provided can't be a valid private key.
    pub fn new<T: Into<BigUint>>(private: T, curve: Curve) -> Result<PrivKey, EccError>{
        let private: BigUint = private.into();
        if private == BigUint::from(0_u8) || &private >= curve.get_n(){
            Err(EccError::InvalidPrivateKey)
        }else{
            Ok(PrivKey{
                private,
                curve
            })
        }
    }
    
    /// Returns the [Curve] the private key refers to
    pub fn get_curve(&self) -> &Curve{
        &self.curve
    }
    
    /// Returns the Private Key
    pub fn get_private(&self) -> &BigUint{
        &self.private
    }

    /// Signs a message using the [PrivKey].
    /// 
    /// Creates a Signature for a message.
    /// 
    /// The message and its type needs to be provided, the type is informed through the [InputType], that is used in the [sha256][crate::sha256] module.
    /// That's because the message needs to be hashed, and the hash is signed with the public key.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::{ecc::*, MyshaError};
    /// use mysha::sha256::InputType;
    /// 
    /// # fn main() -> Result<(), MyshaError>{
    /// let private_key = PrivKey::new(1001001_u32, Curve::secp256k1())?;
    /// let sig = private_key.sign("73", InputType::Decimal)?;
    /// 
    /// println!("{:?}", sig);
    /// 
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// 
    /// This can only emit an [error][EccError] if there is something [wrong] with the curve.
    /// Or if there is a [hashing problem][crate::sha256::HashError].
    /// 
    /// [wrong]: Curve#problematic-curves
    pub fn sign(&self, message: &str, input_type: InputType) -> Result<Signature, MyshaError>{
        let hash = sha256(message, input_type)?;
        let mut rng = rand::rngs::StdRng::from_entropy();
        let curve = self.get_curve();
        let n = curve.get_n().to_bigint().unwrap();
        let random_nonce = rng.gen_bigint_range(&BigInt::from(1_u8), &n);
        let r = get_mod(&curve.multiply(curve.get_g(), random_nonce.clone())?.get_x().unwrap().to_bigint().unwrap(), &n)?;
        let s = get_mod(&(mod_inv(&random_nonce, &n)? * (BigInt::from(&hash) + self.get_private().to_bigint().unwrap() * &r)), &n)?;

        let public = curve.multiply(curve.get_g(), self.get_private().to_bigint().unwrap())?;

        Ok(Signature{
            r: r.to_biguint().unwrap(),
            s: s.to_biguint().unwrap(),
            curve: curve.clone(),
            public,
        })
    }
}

/// Signature Type
/// 
/// Contains the signature and values to validate it.
/// 
/// Can only be created by the methods [KeyPair::sign], [PrivKey::sign] and [new][Signature::new()].
/// 
/// The Signature is made by the "r" and "s" values that are the actual signature values,
/// the curve that it was used to sign, and the public key that signed it, that can be used to verify its validity.
#[derive(Debug)]
pub struct Signature{
    r: BigUint,
    s: BigUint,
    curve: Curve,
    public: Point,
}

impl Signature{
    /// Creates a [Signature]
    /// 
    /// This enables to create a [Signature] type from any signature's values. It needs the "r" and "s" values of the signature,
    /// the curve it was signed on and the public key that signed it, so it can be validated.
    /// 
    /// It can be called on any type that can be converted into a [BigUint], so it needs to be unsigned and an integer.
    /// You can also use [BigUint] itself for bigger numbers.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// use mysha::sha256::{sha256, InputType};
    /// use num_bigint::BigUint;
    /// use num_traits::Num;
    /// 
    /// let r = BigUint::from_str_radix("69871692767452857858836506093862116533449148820094525747386010061201169176830", 10).unwrap();
    /// let s = BigUint::from_str_radix("19672046436037136719602862823761085209313554100053544046333535348499604559220", 10).unwrap();
    /// let curve = Curve::secp256k1();
    /// let public = Point::Point{
    ///     x: BigUint::from_str_radix("397a5ba468b33496b3b8ff5a31b4ff5aabbd35873d3a496598102c26ae950d7b", 16).unwrap(),
    ///     y: BigUint::from_str_radix("a46f8ffcbce897893819dfa9b8ca60b6672e0768588687280d6088ed1f01862d", 16).unwrap(),
    /// };
    /// 
    /// let signature = Signature::new(r, s, curve, public);
    /// ```
    pub fn new<T: Into<BigUint>>(r: T, s: T, curve: Curve, public: Point) -> Signature{

        let r: BigUint = r.into();
        let s: BigUint = s.into();

        Signature{
            r,
            s,
            curve,
            public,
        }
    }
    /// Returns the r part of the signature
    pub fn get_r(&self) -> &BigUint{
        &self.r
    }

    /// Returns the s part of the signature
    pub fn get_s(&self) -> &BigUint{
        &self.s
    }

    /// Returns the curve
    pub fn get_curve(&self) -> &Curve{
        &self.curve
    }

    /// Returns the public key of the signer
    pub fn get_public(&self) -> &Point{
        &self.public
    }

    /// Verifies if the signature is valid for the message provided
    /// 
    /// It checks if the signature is valid for a given message. 
    /// So it checks if the hash of the message is compatible with the signature values "r", "s", and the public key of the signer, 
    /// through elliptic curve math.
    /// # Examples
    /// 
    /// ```
    /// # use mysha::{ecc::*, MyshaError};
    /// # use mysha::sha256::{sha256, InputType};
    /// # use num_bigint::BigUint;
    /// # use num_traits::Num;
    /// # fn main() -> Result<(), MyshaError>{
    /// # let r = BigUint::from_str_radix("69871692767452857858836506093862116533449148820094525747386010061201169176830", 10).unwrap();
    /// # let s = BigUint::from_str_radix("19672046436037136719602862823761085209313554100053544046333535348499604559220", 10).unwrap();
    /// # let curve = Curve::secp256k1();
    /// # let public = Point::Point{
    /// #     x: BigUint::from_str_radix("397a5ba468b33496b3b8ff5a31b4ff5aabbd35873d3a496598102c26ae950d7b", 16).unwrap(),
    /// #     y: BigUint::from_str_radix("a46f8ffcbce897893819dfa9b8ca60b6672e0768588687280d6088ed1f01862d", 16).unwrap(),
    /// # };
    /// # let signature = Signature::new(r, s, curve, public);
    /// assert!(signature.verify("Hello, World!", InputType::Text)?);
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// 
    /// This can only emit an [error][EccError] if there is something [wrong] with the curve.
    /// Or if there is a [hashing problem][crate::sha256::HashError].
    /// 
    /// [wrong]: Curve#problematic-curves
    pub fn verify(&self, message: &str, input_type: InputType) -> Result<bool, MyshaError>{
        let hash = sha256(message, input_type)?;
        let r = self.r.to_bigint().unwrap();
        let s = self.s.to_bigint().unwrap();
        let n = self.curve.get_n().to_bigint().unwrap();
        
        let point1 = self.curve.multiply(self.curve.get_g(), BigInt::from(&hash) * mod_inv(&s, &n)?)?;

        let point2 = self.curve.multiply(&self.public, mod_inv(&s, &n)? * &r)?;

        let point3 = self.curve.add(&point1, &point2)?;

        Ok(point3.get_x() == Some(&self.r))
    }

}
