use std::fmt;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::Num;

/// The error type implemented for this module, with all possible errors that can occur in ecc operations.
#[derive(Debug)]
pub enum EccError{
    /// Happens when a divions by 0 is attempted.
    /// Shouldn't happen, due to the validity checks while creating the curve.
    DivisionByZero,
    /// Happens when the Point provided is not on the curve
    NotOnCurve,
    /// Happens when there is an attempt to set the generator point as the Infinity Point
    GeneratorOnInfinity,
    /// Happens when there is an attemp to set the generator point as a point that isn't in the curve
    GeneratorNotOnCurve,
    /// Happens when attempting to create a singular curve.
    /// 
    /// a singular curve is a [singularity] in the elliptic curves, therefore it doesn't mantain its properties,
    ///  and can't be used for cryptography.
    /// 
    /// it happens when 4a&#179; + 27b&#178; (mod p) = 0;
    /// 
    /// 
    /// [singularity]: https://en.wikipedia.org/wiki/Singularity_(mathematics)
    SingularCurve,
    /// Happens when the private key provided isn't valid
    InvalidPrivateKey,
    /// Happens when there is an attempt to create a public key point as the Point at Infinity
    PublicKeyOnInfinity,
    /// Happens when there is an attempt to create a curve with an invalid order n
    InvalidOrderN,
    /// Happens when either the modulo p, or the order n aren't prime numbers
    /// 
    /// This error can't be catched while creating the curve, it will be found when using the [problematic curve][Curve#problematic-curves]
    NotPrime,
    /// Happens when the signature provided isn't valid
    InvalidSignature,
}

impl fmt::Display for EccError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        match self{
            EccError::DivisionByZero => write!(f, "Division by zero error."),
            EccError::NotOnCurve => write!(f, "Point not on curve error."),
            EccError::GeneratorOnInfinity => write!(f, "Generator point cannot be the point at Infinity."),
            EccError::GeneratorNotOnCurve => write!(f, "Generator not on curve."),
            EccError::SingularCurve => write!(f, "Curve provided is singular."),
            EccError::InvalidPrivateKey => write!(f, "Invalid private key."),
            EccError::PublicKeyOnInfinity => write!(f, "Public key cannot be the point at infinity."),
            EccError::InvalidOrderN => write!(f, "Invalid order of curve, parameter n,"),
            EccError::NotPrime => write!(f, "Modulo p and the order n of the curve must be prime"),
            EccError::InvalidSignature => write!(f, "Invalid signature."),
        }
    }
}

pub fn get_mod(x: &BigInt, p: &BigInt) -> Result<BigInt, EccError>{
    if p == &BigInt::from(0){
        return Err(EccError::DivisionByZero);
    }
    Ok(((x % p) + p) % p) // Rust % is the remainder not mod
}

pub fn mod_inv(a0: &BigInt, p: &BigInt) -> Result<BigInt, EccError>{
    if a0 == &BigInt::from(0){
        return Err(EccError::DivisionByZero);
    }

    let mut m = p.clone();
    let mut a = a0.clone();
    if a < 0.into(){
        a = get_mod(&a, &m)?;
    }

    let (mut y0, mut y) = (BigInt::from(0), BigInt::from(1));

    while a > 1.into(){
        let q: BigInt = &m / &a;
        (y, y0) = (y0 - q * &y, y);
        (a, m) = (m % &a, a);
    }
    let result = get_mod(&y, p)?;
    if get_mod(&(&result * a0), p)? != BigInt::from(1){
        Err(EccError::NotPrime)
    }else{
        Ok(result)
    }
}

/// Point type
/// 
/// Represents a point in the cartesian plane, with the x, and y coordinate.
/// It can also represent the point at infinity, that is the [identity element] of the group, and it doesn't have x or y coordinates.
/// 
/// # Examples
/// ```
/// # use mysha::ecc::Point;
/// use num_bigint::BigUint;
/// let point = Point::Point{x: BigUint::from(10_u8), y: BigUint::from(0_u8)};
/// 
/// println!("{:?}", point);
/// ```
/// [identity element]: https://en.wikipedia.org/wiki/Identity_element
#[derive(Debug, PartialEq, Clone)]
pub enum Point{
    Point{
        x: BigUint,
        y: BigUint,
    },
    PointAtInfinity
}

impl Point{
    /// An easier way to create a [Point]
    /// 
    /// Function that returns a [Point] from the x and y coordinates, using generics, so there is no need to worry about creating a [BigUint].
    /// The input must be positive and unsigned, so it can be converted into a [BigUint].
    /// 
    /// It cannot create the [Infinity Point][Point::PointAtInfinity] variation;
    /// 
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::Point;
    /// let x: u8 = 10; // needs to be u8
    /// let y: u8 = 0;
    /// let p = Point::point(x, y);
    /// println!("{:?}", p);
    /// ```
    pub fn point<T: Into<BigUint>>(x: T, y:T) -> Point{
        Point::Point { x: x.into(), y: y.into() }
    }
    
    /// Returns the x coordinate
    /// 
    /// Returns [Some] if there is an x coordinate, 
    /// and returns [None] if the point is the [point at infinity][Point::PointAtInfinity].
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::Point;
    /// use num_bigint::BigUint;
    /// let p1 = Point::point(2_u8, 3_u8);
    /// let x = p1.get_x().expect("Point at infinity");
    /// 
    /// assert_eq!(x, &BigUint::from(2_u8));
    /// ```
    pub fn get_x(&self) -> Option<&BigUint>{
        match self{
            Point::PointAtInfinity => None,
            Point::Point { x, .. } => Some(x),
        }
    }
    /// Returns the y coordinate
    /// 
    /// Returns [Some] if there is an y coordinate, 
    /// and returns [None] if the point is the [point at infinity][Point::PointAtInfinity].
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::Point;
    /// use num_bigint::BigUint;
    /// let p1 = Point::point(2_u8, 3_u8);
    /// let y = p1.get_y().expect("Point at infinity");
    /// 
    /// assert_eq!(y, &BigUint::from(3_u8));
    /// ```
    pub fn get_y(&self) -> Option<&BigUint>{
        match self{
            Point::PointAtInfinity => None,
            Point::Point { y, .. } => Some(y),
        }
    }
    /// Returns both x and y coordinates
    /// 
    /// Returns [Some] if the coordinates exist,
    /// and returns [None] if the point is the [point at infinity][Point::PointAtInfinity]
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::Point;
    /// use num_bigint::BigUint;
    /// let p = Point::point(1_u8, 10_u8);
    /// let (x, y) = p.get_xy().expect("Point at infinity");
    /// 
    /// assert_eq!((x, y), (&BigUint::from(1_u8), &BigUint::from(10_u8)));
    /// ```
    pub fn get_xy(&self) -> Option<(&BigUint, &BigUint)>{
        match self{
            Point::PointAtInfinity => None,
            Point::Point { x, y } => Some((x, y)),
        }
    }

    fn point_neg<T: Into<BigInt>>(&self, prime: T) -> Result<Point, EccError>{
        let prime: BigInt = prime.into();
        match self{
            Point::Point{x, y} => Ok(Point::Point{x: x.clone(), y: (get_mod(&-y.to_bigint().unwrap(), &prime)?).to_biguint().unwrap()}),
            Point::PointAtInfinity => Ok(Point::PointAtInfinity),
        }
    }
}

/// Elliptic Curve type
/// 
/// Contains all the parameters that define an [elliptic curve]
/// 
/// To create a Curve, refer to [new][Curve::new], or to to [secp256k1()][Curve::secp256k1], to use the [secp256k1] standard curve.
/// This methods are necessary to create a Curve, 
/// since the fields are private to ensure that only valid elliptic curves are created.
/// 
/// The Curve type is present in most of the other ecc types, as they would be meaningless without its respective originating curve to bound to.
/// 
/// # Parameters
/// 
/// - the parameters "a" and "b" define the elliptic curve equation, in y&#178; = x&#179; + ax + b (mod p);
/// - the parameter "p" defines the field of the elliptic curve, so the elliptic curve is (mod p);
/// - the parameter "g" is the curves Generator point, it is a [Point] that is used to start the ecc operations.
/// - the parameter "n" is the order of the subgroup generated by the curve and the generator point, 
/// it is a result of the other parameters, but it needs to be calculated and provided.
/// 
/// # Problematic curves
/// It is worth pointing out, that when creating a curve it is possible to create a problematic curve, despite the verifications made to ensure the curve is valid.
/// This happens because the p and the n parameters might no be prime for the curve in question, and it is infeasable to always check if theese parameters are prime numbers
/// in the process of verifying the curve.
/// 
/// Problematic curves aren't fit for cryptography, and can cause an [NotPrime][EccError::NotPrime] when doing operations with them, to fix that 
/// make sure your curve has prime parameters n and p, and it is a valid curve.
/// 
/// 
/// [secp256k1]: https://www.secg.org/sec2-v2.pdf#Recommended%20Parameters%20secp256k1
/// [elliptic curve]: https://en.wikipedia.org/wiki/Elliptic_curve
#[derive(Debug, Clone)]
pub struct Curve{
    a: i32,
    b: i32,
    p: BigUint,
    n: BigUint,
    g: Point,
}

impl Curve{
    /// Creates a new [Curve] from the curve [parameters]
    /// 
    /// It can be called on any type that can be converted into a [BigUint], so
    /// it needs to be unsigned and an integer. You can also use [BigUint] itself for bigger numbers.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// let c = Curve::new(2, 3, 97_u32, 50_u32, Point::point(0_u32, 10_u32));
    /// ```
    /// # Errors
    /// This can fail if the elliptic curve isn't valid, or [good for cryptography].
    /// 
    /// [good for cryptography]: #problematic-curves
    /// [parameters]: #parameters
    pub fn new<T: Into<BigInt> + Into<BigUint>> (a:i32, b: i32, p: T, n: T, g: Point) -> Result<Curve, EccError>{
        let p: BigUint = p.into();
        let n: BigUint = n.into();
        
        if g == Point::PointAtInfinity{
            return Err(EccError::GeneratorOnInfinity);
        }
        
        if get_mod(&BigInt::from(4 * a.pow(3) + 27 * b.pow(2)), &p.to_bigint().unwrap())? == BigInt::from(0){
            return Err(EccError::SingularCurve);
        }

        if n == BigUint::from(0_u8){
            return Err(EccError::InvalidOrderN);
        }

        let curve = Curve{
            a,
            b,
            p,
            n,
            g,
        };

        if curve.multiply(&curve.g, curve.n.to_bigint().unwrap())? != Point::PointAtInfinity{
            return Err(EccError::InvalidOrderN)
        }
        if ! curve.is_on_curve(&curve.g){
            return Err(EccError::GeneratorNotOnCurve);
        }

        Ok(curve)
    }

    /// Returns the value of the [parameter](#parameters) "a"
    pub fn get_a(&self) -> i32{
        self.a
    }

    /// Returns the value of the [parameter](#parameters) "b"
    pub fn get_b(&self) -> i32{
        self.b
    }

    /// Returns the value of the [parameter](#parameters) "p"
    pub fn get_p(&self) -> &BigUint{
        &self.p
    }

    /// Returns the value of the [parameter](#parameters) "n"
    pub fn get_n(&self) -> &BigUint{
        &self.n
    }

    /// Returns the [generator point](#parameters)
    pub fn get_g(&self) -> &Point{
        &self.g
    }

    /// Returns a [Curve] with the [secp256k1] specs
    /// 
    /// [secp256k1]: https://www.secg.org/sec2-v2.pdf#Recommended%20Parameters%20secp256k1
    pub fn secp256k1() -> Curve{
        Curve{
            a: 0,
            b: 7,
            p: BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap(),
            n: BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap(),
            g: Point::Point {
                x: BigUint::from_str_radix("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
                y: BigUint::from_str_radix("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
            },
        }
    }

    /// Returns a [bool] value that indicates wether the point provided is on the curve
    /// 
    /// # Examples
    /// 
    /// ```
    /// # use mysha::ecc::*;
    /// # fn main() -> Result<(), EccError>{
    /// # let c = Curve::new(2, 3, 97_u32, 50_u32, Point::point(0_u32, 10_u32))?;
    /// let on_curve = c.is_on_curve(&Point::point(10_u32, 76_u32));
    /// assert!(on_curve);
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_on_curve(&self, p: &Point) -> bool{
        match p{
            Point::Point{x, y} => {
                let x = x.to_bigint().unwrap();
                let y = y.to_bigint().unwrap();
                let prime = self.p.to_bigint().unwrap();
                (y.pow(2) - x.pow(3) -  &x * self.a - self.b) % prime == BigInt::from(0)
            },
            Point::PointAtInfinity => true,
        }
    }

    /// Adds two [points][Point] on the [Curve]
    /// 
    /// Perform the elliptic curve addition operation on the two points provided.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// # fn main() -> Result<(), EccError>{
    /// # let c = Curve::new(2, 3, 97_u32, 50_u32, Point::point(0_u32, 10_u32))?;
    /// let sum = c.add(&Point::point(17_u32, 10_u32), &Point::point(95_u32, 31_u32))?;
    /// assert_eq!(sum, Point::point(1_u32, 54_u32));
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// This can fail if the points provided aren't on the curve, or if there is [something wrong] with the curve.
    /// 
    /// [something wrong]: #problematic-curves
    pub fn add(&self, p: &Point, q: &Point) -> Result<Point, EccError>{
        if !(self.is_on_curve(p) && self.is_on_curve(q)){
            return Err(EccError::NotOnCurve)
        }
        
        if p == q{
            return self.double(p);
        }
        match p{
            Point::Point{x: px, y: py} => {
                let px = px.to_bigint().unwrap();
                let py = py.to_bigint().unwrap();
                match q{
                    Point::Point{x: qx, y: qy} => {
                        let prime = self.p.to_bigint().unwrap();
                        let qx = qx.to_bigint().unwrap();
                        let qy = qy.to_bigint().unwrap();
                        if px == qx{
                            return Ok(Point::PointAtInfinity);
                        }

                        let slope = get_mod(&((&py - &qy) * mod_inv(&(&px - &qx), &prime)?), &prime)?;

                        let x = get_mod(&(slope.pow(2) - &px - &qx), &prime)?;

                        let y = get_mod(&(&slope * (&px - &x) - &py), &prime)?;

                        Ok(Point::Point{
                            x: x.try_into().unwrap(),
                            y: y.try_into().unwrap(),
                        })
                    },
                    Point::PointAtInfinity => Ok(p.clone()),
                }
            },
            Point::PointAtInfinity => Ok(q.clone()),
        }
    }

    /// Doubles a [Point] on the [Curve]
    /// 
    /// Performs the elliptic curve double operation on the point provided.
    /// Equivalent to adding two equal points.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// # fn main() -> Result<(), EccError>{
    /// # let c = Curve::new(2, 3, 97_u32, 50_u32, Point::point(0_u32, 10_u32))?;
    /// let double = c.double(&Point::point(24_u32, 2_u32))?;
    /// assert_eq!(double, Point::point(65_u32, 65_u32));
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    /// This can fail if the point provided isn't on the curve, or if there is a [problem] with the curve.
    /// 
    /// [problem]: #problematic-curves
    pub fn double(&self, p: &Point) -> Result<Point, EccError>{
        if !self.is_on_curve(p){
            return Err(EccError::NotOnCurve);
        }

        match p{
            Point::Point{x, y} => {
                let x = x.to_bigint().unwrap();
                let y = y.to_bigint().unwrap();
                if y == BigInt::from(0){
                    return Ok(Point::PointAtInfinity);
                }
                let prime = self.p.to_bigint().unwrap();
                let slope = get_mod(&((x.pow(2) * 3 + self.a) * mod_inv(&(2 * &y), &prime)?), &prime)?;
                let x1 = get_mod(&(slope.pow(2) - 2 * &x), &prime)?;
                let y1 = get_mod(&(&slope * (&x - &x1) - &y), &prime)?;
                Ok(Point::Point {
                    x: x1.try_into().unwrap(),
                    y: y1.try_into().unwrap(),
                })
            },
            Point::PointAtInfinity => Ok(Point::PointAtInfinity),
        }
        
    }

    /// Multiples a [Point] with a scalar number, on the [Curve]
    /// 
    /// Performs the multiplication opperation, that consists of multiple add and double operations.
    /// 
    /// It can be called on any type that can be converted into a [BigInt], so it needs to be an integer.
    /// You can also use [BigInt] itself for bigger numbers.
    /// 
    /// # Examples
    /// ```
    /// # use mysha::ecc::*;
    /// # fn main() -> Result<(), EccError>{
    /// # let c = Curve::new(2, 3, 97_u32, 50_u32, Point::point(0_u32, 10_u32))?;
    /// let n = c.multiply(c.get_g(), 35)?;
    /// assert_eq!(n, Point::point(53_u32, 73_u32));
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    /// This can fail if the Point provided isn't on the curve, or if there is a [problem] with the curve. 
    /// 
    /// [problem]: #problematic-curves
    pub fn multiply<T: Into<BigInt>>(&self, p: &Point, k: T) -> Result<Point, EccError>{
        let k: BigInt = k.into();
        if &k == &BigInt::from(0){
            return Ok(Point::PointAtInfinity);
        }

        let mut p = p.clone();
        let mut bits = format!("{:b}", k);
        if &k < &BigInt::from(0){
            p = p.point_neg( self.p.to_bigint().unwrap())?;
            bits = format!("{:b}", -k);
        }
        let mut current = p.clone();
        for i in bits[1..].chars(){
            current = self.double(&current)?;
            if i == '1'{
                current = self.add(&current, &p)?;
            }
        }
        Ok(current)
    }

}
