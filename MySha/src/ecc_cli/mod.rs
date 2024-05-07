use clap::{Args, Subcommand};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Num, ToBytes};
use std::{num::ParseIntError, str::FromStr};
use rand::{self, SeedableRng};

use mysha::ecc::{self, Curve, KeyPair, Point, PubKey, PrivKey, Signature};
use mysha::sha256;
use crate::Exit;
use crate::sha256_cli;

mod output;
use self::output::{from_toml, to_toml, OutputTomlFile};


#[derive(Args, Debug)]
pub struct ECCArgs{
    #[command(subcommand)]
    subcommand: SubCommand,

    /// output file for the key pair.
    #[arg(short, long)]
    output: Option<String>,

    /// Turns off the safety error when trying to overwrite private key files.
    #[arg(long)]
    overwrite: bool,

    /// path to toml file with curve specs. Defaults to secp256k1. Structure avaiable with new curve command.
    #[arg(short, long)]
    curve: Option<String>,

    /// Displays output as hex
    #[arg(long)]
    hex: bool,

    /// Displays output as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
} 

#[derive(Debug, Subcommand)]
enum SubCommand{
    /// Generate new key pair from a private key, or a random one
    Generate(GenArgs),
    /// Sign message
    Sign(SignArgs),
    /// Verify signature with message
    Verify(VerifyArgs),
    /// Create new toml objects
    New(NewArgs),
}

#[derive(Args, Debug)]
struct NewArgs{
    #[command(subcommand)]
    object: Objects,
}

#[derive(Debug, Subcommand)]
enum Objects{
    /// outputs curve toml object, defaults to secp256k1
    Curve(CurveArgs),
    /// outputs keypair toml object
    KeyPair(KeyPairArgs),
    /// outputs public key toml object
    PubKey(PubKeyArgs),
    /// outputs private key toml object
    PrivKey(PrivKeyArgs),
    /// outputs signature toml object
    Signature(SigArgs),
}

#[derive(Args, Debug)]
struct CurveArgs{
    /// a parameter of curve
    #[arg(short)]
    a: Option<i32>,

    /// b parameter of curve
    #[arg(short)]
    b: Option<i32>,
    
    /// prime modulo of curve
    #[arg(short)]
    p: Option<String>,

    /// Order of the curve
    #[arg(short)]
    n: Option<String>,

    /// x coordinate of the generator point
    #[arg(short)]
    x: Option<String>,

    /// y coordinate of the generator point
    #[arg(short)]
    y: Option<String>,

    /// treats curve parameters as hex
    #[arg(long)]
    hex: bool,

    /// treats curve parameters as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct KeyPairArgs{
    /// private key
    #[arg(short, long)]
    private: String,

    /// x coordinate of public key
    #[arg(short)]
    x: String,
    
    /// y coordinate of public key
    #[arg(short)]
    y: String,

    /// treats input values as hex
    #[arg(long)]
    hex: bool,

    /// treats input values as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct PubKeyArgs{
    /// x coordinate of public key
    #[arg(short)]
    x: String,

    /// y coordinate of public key
    #[arg(short)]
    y: String,

    /// treats input values as hex
    #[arg(long)]
    hex: bool,

    /// treats input values as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct PrivKeyArgs{
    /// private key scalar number
    private: String,

    /// treats input values as hex
    #[arg(long)]
    hex: bool,

    /// treats input values as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct SigArgs{
    /// x coordinate of the public key that produced the signature
    #[arg(short)]
    x: String,

    /// y coordinate of the public key that produced the signature
    #[arg(short)]
    y: String,

    /// signature r part 
    #[arg(short)]
    r: String,

    /// signature s part 
    #[arg(short)]
    s: String,

    /// treats input values as hex
    #[arg(long)]
    hex: bool,

    /// treats input values as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct GenArgs{
    /// Private key to create key pair or type "random" to generate random private key
    private: Option<String>,
    /// treats input numbers as hex
    #[arg(long)]
    hex: bool,
    /// treats input number as little endian. Needs to have hex enabled.
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Args, Debug)]
struct SignArgs{
    /// Message to be signed
    message: String,
    /// Private Key or key pair file
    #[arg(short, long)]
    private: String,
    /// Message type
    #[arg(short, long, default_value_t = sha256_cli::Type::Text, value_enum)]
    r#type: sha256_cli::Type,
}

#[derive(Args, Debug)]
struct VerifyArgs{
    /// Signature file to be verified
    signature: String,
    /// Message signed for the provided signature
    #[arg(short, long)]
    message: String,
    /// message type
    #[arg(short, long, default_value_t = sha256_cli::Type::Text, value_enum)]
    r#type: sha256_cli::Type,
}

fn get_biguint(n: &str, hex: bool, le: bool) -> BigUint{
    if hex{
        if le{
            if n.len() % 2 != 0{
                eprintln!("Error while parsing large integers: you are not able to use little endian, since you did not provide a whole number of bytes.");
                std::process::exit(1);
            }
            (0..n.len()).step_by(2).map(|b| u8::from_str_radix(&n[b..b + 2], 16)).collect::<Result<Vec<u8>, ParseIntError>>().map(|b| BigUint::from_bytes_le(&b)).ok()
        }else{
            BigUint::from_str_radix(n, 16).ok()
        }
    }else{
        BigUint::from_str(n).ok()
    }.exit("Error while parsing large integers.")
}

pub fn key_pair(args: ECCArgs){
    let hex = args.hex;
    let le = args.little_endian;
    let curve = if let Some(path) = &args.curve{
        let input = from_toml(path);
        input.to_curve()
    }else{
        ecc::Curve::secp256k1()
    };

    match args.subcommand{
        SubCommand::New(sub_args) => {
            let output = match sub_args.object{
                Objects::Curve(specs) => {
                    let mut a = curve.get_a();
                    let mut b = curve.get_b();
                    let mut p = curve.get_p().clone();
                    let mut n = curve.get_n().clone();
                    let g = curve.get_g();
                    let mut x = g.get_x().unwrap().clone();
                    let mut y = g.get_y().unwrap().clone();

            
                    if let Some(value) = specs.a{
                        a = value;
                    }
                    if let Some(value) = specs.b{
                        b = value;
                    }
                    if let Some(value) = specs.p{
                        p = get_biguint(&value, specs.hex, specs.little_endian);
                    }
                    if let Some(value) = specs.n{
                        n = get_biguint(&value, specs.hex, specs.little_endian);
                    }
                    if let Some(value) = specs.x{
                        x = get_biguint(&value, specs.hex, specs.little_endian);
                    }
                    if let Some(value) = specs.y{
                        y = get_biguint(&value, specs.hex, specs.little_endian);
                    }
                    let g = Point::point(x, y);

                    let curve = Curve::new(a, b, p, n, g).exit("Invalid Curve parameters.");
                    OutputTomlFile::from_curve(&curve, hex, le)
                },
                Objects::KeyPair(specs) => {
                    let x = get_biguint(&specs.x, specs.hex, specs.little_endian);
                    let y = get_biguint(&specs.y, specs.hex, specs.little_endian);
                    let public = Point::Point { x, y};
                    let private = get_biguint(&specs.private, specs.hex, specs.little_endian);
                    let kp = KeyPair::new(private, curve).exit("Invalid Key Pair.");
                    if kp.get_public() != &public{
                        Err::<KeyPair, &str>("Public key doesn't match private key provided.").exit("Invalid Key Pair.");
                    }
                    OutputTomlFile::from_key_pair(&kp, hex, le)
                    
                },
                Objects::PubKey(specs) => {
                    let x = get_biguint(&specs.x, specs.hex, specs.little_endian);
                    
                    let y = get_biguint(&specs.y, specs.hex, specs.little_endian);

                    let public = Point::Point{
                        x,
                        y,
                    };
                    let p = PubKey::new(public, curve).exit("Invalid Public Key.");
                    OutputTomlFile::from_public(&p, hex, le)
                },
                Objects::PrivKey(specs) => {
                    let n = get_biguint(&specs.private, specs.hex, specs.little_endian);
                    let p = PrivKey::new(n, curve).exit("Invalid Private Key.");
                    OutputTomlFile::from_private(&p, hex, le)
                },
                Objects::Signature(specs) => {
                    let x = get_biguint(&specs.x, specs.hex, specs.little_endian);
                    let y = get_biguint(&specs.y, specs.hex, specs.little_endian);
                    let r = get_biguint(&specs.r, specs.hex, specs.little_endian);
                    let s = get_biguint(&specs.s, specs.hex, specs.little_endian);
                    let public = Point::Point { x, y };
                    let sig = Signature::new(r, s, curve, public);
                    OutputTomlFile::from_sig(&sig, hex, le)
                },
            };
            if let Some(filename) = args.output{
                to_toml(output, &filename, false);
            }else{
                println!("{}", toml::to_string(&output).exit("Error while parsing to toml."));
            }
        },
        SubCommand::Generate(sub_args) => {
            let private = sub_args.private.unwrap_or(String::from("random"));
            if private.to_lowercase() == "random" {
                let mut rng = rand::rngs::StdRng::from_entropy();
                let private = rng.gen_biguint_range(&BigUint::from(1_u8), curve.get_n());
                let kp = KeyPair::new(private, curve).exit("Encountered");
                if let Some(filename) = args.output{
                    let output = OutputTomlFile::from_key_pair(&kp, hex, le);
                    to_toml(output, &filename, ! args.overwrite);
                }else{
                    if hex{
                        if le{
                            println!("private key: {}\nPublic Key: Point {{\n    x: {},\n    y: {},\n}}", &kp.get_private().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>(), &kp.get_public().get_x().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>(), &kp.get_public().get_y().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>());
                        }else{
                            println!("private key: {:x}\nPublic Key: Point {{\n    x: {:x},\n    y: {:x},\n}}", &kp.get_private(), &kp.get_public().get_x().unwrap(), &kp.get_public().get_y().unwrap());
                        }
                    }else{
                        println!("private key: {}\nPublic Key: {:#?}",&kp.get_private(), &kp.get_public());
                    }
                }
            }else{
                let multiplier = get_biguint(&private, sub_args.hex, sub_args.little_endian);
                let kp = KeyPair::new(multiplier, curve).exit("Encoutered");
                if let Some(filename) = args.output{
                    let output = OutputTomlFile::from_key_pair(&kp, sub_args.hex, sub_args.little_endian);
                    to_toml(output, &filename, ! args.overwrite)
                }else{
                    if hex{
                        if le{
                            println!("Public Key: Point {{\n    x: {},\n    y: {},\n}}", &kp.get_public().get_x().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>(), &kp.get_public().get_y().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>());
                        }else{
                            println!("Public Key: Point {{\n    x: {:x},\n    y: {:x},\n}}", &kp.get_public().get_x().unwrap(), &kp.get_public().get_y().unwrap());
                        }
                    }else{
                        println!("Public Key: {:#?}", &kp.get_public());
                    }
                }
            }
        },
        SubCommand::Sign(sub_args) => {
            let private = from_toml(&sub_args.private);
            let private = private.to_priv_key();
            let t = match sub_args.r#type{
                sha256_cli::Type::Text => sha256::InputType::Text,
                sha256_cli::Type::Binary => sha256::InputType::Binary,
                sha256_cli::Type::LeBinary => sha256::InputType::LeBinary,
                sha256_cli::Type::File => sha256::InputType::File,
                sha256_cli::Type::Hex => sha256::InputType::Hex,
                sha256_cli::Type::LeHex => sha256::InputType::LeHex,
                sha256_cli::Type::Decimal => sha256::InputType::Decimal,
            };
            let sig = private.sign(&sub_args.message, t).exit("Encountered");
            if let Some(filename) = args.output{
                let output = OutputTomlFile::from_sig(&sig, hex, le);
                to_toml(output, &filename, false);
            }else{
                if hex{
                    if le{
                        println!("r: {}\ns: {}", sig.get_r().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>(), sig.get_s().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>())  
                    }else{    
                        println!("r: {:x}\ns: {:x}", sig.get_r(), sig.get_s());
                    }
                }else{
                    println!("r: {}\ns: {}", sig.get_r(), sig.get_s());
                }
            }
        },
        SubCommand::Verify(sub_args) => {
            let signature = from_toml(&sub_args.signature);
            let signature = signature.to_sig();
            let t = match sub_args.r#type{
                sha256_cli::Type::Text => sha256::InputType::Text,
                sha256_cli::Type::Binary => sha256::InputType::Binary,
                sha256_cli::Type::LeBinary => sha256::InputType::LeBinary,
                sha256_cli::Type::File => sha256::InputType::File,
                sha256_cli::Type::Hex => sha256::InputType::Hex,
                sha256_cli::Type::LeHex => sha256::InputType::LeHex,
                sha256_cli::Type::Decimal => sha256::InputType::Decimal,
            };
            if signature.verify(&sub_args.message, t).exit("Error while hashing message"){
                println!("Signature IS valid");
            }else{
                println!("Signature is NOT valid");
            }
        },
    }
}
