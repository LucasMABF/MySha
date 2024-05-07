use std::{fs::File, io::{Read, Write}};

use num_traits::ToBytes;
use serde::{Serialize, Deserialize};

use crate::Exit;
use mysha::ecc::{Curve, KeyPair, Point, PrivKey, Signature, PubKey};

use super::get_biguint;

#[derive(Serialize, Deserialize, Debug)]
pub struct CurveToml{
    pub a: i32,
    pub b: i32,
    pub p: String,
    pub n: String,
    pub x: String,
    pub y: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FlagsToml{
    pub hex: Option<bool>,
    pub little_endian: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OutputTomlFile{
    pub key_pair: Option<KeyPairToml>,
    pub signature: Option<SignatureToml>,
    pub curve: CurveToml,
    pub flags: Option<FlagsToml>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPairToml{
    pub public: Option<(String, String)>,
    pub private: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureToml{
    r: String,
    s: String,
}

impl OutputTomlFile{
    pub fn from_curve(c: &Curve, hex: bool, le: bool) -> OutputTomlFile{
        let (x, y) = c.get_g().get_xy().unwrap();
        if hex == true{
            if le{
                OutputTomlFile{
                    curve: CurveToml{
                        a: c.get_a(),
                        b: c.get_b(),
                        p: c.get_p().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        n: c.get_n().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        x: x.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        y: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    },
                    key_pair: None,
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(true),
                    }),
                    signature: None,
                }
            }else{
                OutputTomlFile{
                    curve: CurveToml{
                        a: c.get_a(),
                        b: c.get_b(),
                        p: c.get_p().to_str_radix(16),
                        n: c.get_n().to_str_radix(16),
                        x: x.to_str_radix(16),
                        y: y.to_str_radix(16),
                    },
                    key_pair: None,
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(false),
                    }),
                    signature: None,
                }
            }
        }else{
            OutputTomlFile{
                curve: CurveToml{
                    a: c.get_a(),
                    b: c.get_b(),
                    p: c.get_p().to_string(),
                    n: c.get_n().to_string(),
                    x: x.to_string(),
                    y: y.to_string(),
                },
                key_pair: None,
                flags: Some(FlagsToml{
                    hex: Some(false),
                    little_endian: None,
                }),
                signature: None,
            }
        }
    }

    pub fn from_key_pair(k: &KeyPair, hex: bool, le: bool) -> OutputTomlFile{
        let (x, y) = k.get_curve().get_g().get_xy().unwrap();
        if hex{
            if le{
                OutputTomlFile{
                    curve: CurveToml{
                        a: k.get_curve().get_a(),
                        b: k.get_curve().get_b(),
                        p: k.get_curve().get_p().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        n: k.get_curve().get_n().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        x: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        y: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((k.get_public().get_x().unwrap().to_str_radix(16), k.get_public().get_y().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect())),
                        private: Some(k.get_private().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect()),
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(true),
                    }),
                    signature: None,
                }
            }else{
                OutputTomlFile{
                    curve: CurveToml{
                        a: k.get_curve().get_a(),
                        b: k.get_curve().get_b(),
                        p: k.get_curve().get_p().to_str_radix(16),
                        n: k.get_curve().get_n().to_str_radix(16),
                        x: x.to_str_radix(16),
                        y: y.to_str_radix(16),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((k.get_public().get_x().unwrap().to_str_radix(16), k.get_public().get_y().unwrap().to_str_radix(16))),
                        private: Some(k.get_private().to_str_radix(16)),
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(false),
                    }),
                    signature: None,
                }
            }
        }else{
            OutputTomlFile{
                curve: CurveToml{
                    a: k.get_curve().get_a(),
                    b: k.get_curve().get_b(),
                    p: k.get_curve().get_p().to_string(),
                    n: k.get_curve().get_n().to_string(),
                    x: x.to_string(),
                    y: y.to_string(),
                },
                key_pair: Some(KeyPairToml{
                    public: Some((k.get_public().get_x().unwrap().to_string(), k.get_public().get_y().unwrap().to_string())),
                    private: Some(k.get_private().to_string()),
                }),
                flags: Some(FlagsToml{
                    hex: Some(false),
                    little_endian: None,
                }),
                signature: None,
            }
        }
    }

    pub fn from_sig(sig: &Signature, hex: bool, le: bool) -> OutputTomlFile{
        let (x, y) = sig.get_curve().get_g().get_xy().unwrap();
        if hex{
            if le{
                OutputTomlFile{
                    curve: CurveToml{
                        a: sig.get_curve().get_a(),
                        b: sig.get_curve().get_b(),
                        p: sig.get_curve().get_p().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        n: sig.get_curve().get_n().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        x: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        y: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((sig.get_public().get_x().unwrap().to_str_radix(16), sig.get_public().get_y().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect())),
                        private: None,
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(true),
                    }),
                    signature: Some(SignatureToml{
                        r: sig.get_r().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        s: sig.get_s().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    }),
                }
            }else{
                OutputTomlFile{
                    curve: CurveToml{
                        a: sig.get_curve().get_a(),
                        b: sig.get_curve().get_b(),
                        p: sig.get_curve().get_p().to_str_radix(16),
                        n: sig.get_curve().get_n().to_str_radix(16),
                        x: x.to_str_radix(16),
                        y: y.to_str_radix(16),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((sig.get_public().get_x().unwrap().to_str_radix(16), sig.get_public().get_y().unwrap().to_str_radix(16))),
                        private: None,
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(false),
                    }),
                    signature: Some(SignatureToml{
                        r: sig.get_r().to_str_radix(16),
                        s: sig.get_s().to_str_radix(16),
                    }),
                }
            }
        }else{
            OutputTomlFile{
                curve: CurveToml{
                    a: sig.get_curve().get_a(),
                    b: sig.get_curve().get_b(),
                    p: sig.get_curve().get_p().to_string(),
                    n: sig.get_curve().get_n().to_string(),
                    x: x.to_string(),
                    y: y.to_string(),
                },
                key_pair: Some(KeyPairToml{
                    public: Some((sig.get_public().get_x().unwrap().to_string(), sig.get_public().get_y().unwrap().to_string())),
                    private: None,
                }),
                flags: Some(FlagsToml{
                    hex: Some(false),
                    little_endian: None,
                }),
                signature: Some(SignatureToml{
                    r: sig.get_r().to_string(),
                    s: sig.get_s().to_string(),
                }),
            }
        }
    }

    pub fn from_public(p: &PubKey, hex: bool, le: bool) -> OutputTomlFile{
        let (x, y) = p.get_curve().get_g().get_xy().unwrap();
        if hex{
            if le{
                OutputTomlFile{
                    curve: CurveToml{
                        a: p.get_curve().get_a(),
                        b: p.get_curve().get_b(),
                        p: p.get_curve().get_p().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        n: p.get_curve().get_n().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        x: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        y: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((p.get_public().get_x().unwrap().to_str_radix(16), p.get_public().get_y().unwrap().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect())),
                        private: None,
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(true),
                    }),
                    signature: None,
                }
            }else{
                OutputTomlFile{
                    curve: CurveToml{
                        a: p.get_curve().get_a(),
                        b: p.get_curve().get_b(),
                        p: p.get_curve().get_p().to_str_radix(16),
                        n: p.get_curve().get_n().to_str_radix(16),
                        x: x.to_str_radix(16),
                        y: y.to_str_radix(16),
                    },
                    key_pair: Some(KeyPairToml{
                        public: Some((p.get_public().get_x().unwrap().to_str_radix(16), p.get_public().get_y().unwrap().to_str_radix(16))),
                        private: None,
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(false),
                    }),
                    signature: None,
                }
            }
        }else{
            OutputTomlFile{
                curve: CurveToml{
                    a: p.get_curve().get_a(),
                    b: p.get_curve().get_b(),
                    p: p.get_curve().get_p().to_string(),
                    n: p.get_curve().get_n().to_string(),
                    x: x.to_string(),
                    y: y.to_string(),
                },
                key_pair: Some(KeyPairToml{
                    public: Some((p.get_public().get_x().unwrap().to_string(), p.get_public().get_y().unwrap().to_string())),
                    private: None,
                }),
                flags: Some(FlagsToml{
                    hex: Some(false),
                    little_endian: None,
                }),
                signature: None,
            }
        }
    }

    pub fn from_private(p: &PrivKey, hex: bool, le: bool) -> OutputTomlFile{
        let (x, y) = p.get_curve().get_g().get_xy().unwrap();
        if hex{
            if le{
                OutputTomlFile{
                    curve: CurveToml{
                        a: p.get_curve().get_a(),
                        b: p.get_curve().get_b(),
                        p: p.get_curve().get_p().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        n: p.get_curve().get_n().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        x: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                        y: y.to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
                    },
                    key_pair: Some(KeyPairToml{
                        public: None,
                        private: Some(p.get_private().to_le_bytes().iter().map(|b| format!("{:02x}", b)).collect()),
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(true),
                    }),
                    signature: None,
                }
            }else{
                OutputTomlFile{
                    curve: CurveToml{
                        a: p.get_curve().get_a(),
                        b: p.get_curve().get_b(),
                        p: p.get_curve().get_p().to_str_radix(16),
                        n: p.get_curve().get_n().to_str_radix(16),
                        x: x.to_str_radix(16),
                        y: y.to_str_radix(16),
                    },
                    key_pair: Some(KeyPairToml{
                        public: None,
                        private: Some(p.get_private().to_str_radix(16)),
                    }),
                    flags: Some(FlagsToml{
                        hex: Some(true),
                        little_endian: Some(false),
                    }),
                    signature: None,
                }
            }
        }else{
            OutputTomlFile{
                curve: CurveToml{
                    a: p.get_curve().get_a(),
                    b: p.get_curve().get_b(),
                    p: p.get_curve().get_p().to_string(),
                    n: p.get_curve().get_n().to_string(),
                    x: x.to_string(),
                    y: y.to_string(),
                },
                key_pair: Some(KeyPairToml{
                    public: None,
                    private: Some(p.get_private().to_string()),
                }),
                flags: Some(FlagsToml{
                    hex: Some(false),
                    little_endian: None,
                }),
                signature: None,
            }
        }
    }

    pub fn to_curve(self) -> Curve{
        let (hex, le): (bool, bool) = match self.flags{
            Some(flag) => (flag.hex.unwrap_or(false), flag.little_endian.unwrap_or(false)),
            None => (false, false),
        };
        
        Curve::new(
            self.curve.a,
            self.curve.b, 
            get_biguint(&self.curve.p, hex, le), 
            get_biguint(&self.curve.n, hex, le), 
            Point::Point { 
                x: get_biguint(&self.curve.x, hex, le), 
                y: get_biguint(&self.curve.y, hex, le), 
            }
        ).exit("Invalid Curve parameters.")
    }

    pub fn to_priv_key(self) -> PrivKey{
        let (hex, le): (bool, bool) = match &self.flags{
            Some(flag) => (flag.hex.unwrap_or(false), flag.little_endian.unwrap_or(false)),
            None => (false, false),
        };

        let curve = Curve::new(
            self.curve.a,
            self.curve.b, 
            get_biguint(&self.curve.p, hex, le), 
            get_biguint(&self.curve.n, hex, le), 
            Point::Point { 
                x: get_biguint(&self.curve.x, hex, le), 
                y: get_biguint(&self.curve.y, hex, le), 
            }
        ).exit("Invalid Curve parameters.");

        PrivKey::new(get_biguint(&self.key_pair.exit("Private Key required for signing.").private.exit("Private Key required for signing."), hex, le), curve).unwrap()
    }

    pub fn to_sig(self) -> Signature{
        let(hex, le) = match &self.flags{
            Some(flag) => (flag.hex.unwrap_or(false), flag.little_endian.unwrap_or(false)),
            None => (false, false),
        };

        let curve = Curve::new(
            self.curve.a,
            self.curve.b,
            get_biguint(&self.curve.p, hex, le),
            get_biguint(&self.curve.n, hex, le),
            Point::Point{
                x: get_biguint(&self.curve.x, hex, le),
                y: get_biguint(&self.curve.y, hex, le),
            }
        ).exit("Invalid Curve parameters");

        let sig = self.signature.exit("Signature field necessary.");

        let r = get_biguint(&sig.r, hex, le);
        let s = get_biguint(&sig.s, hex, le);
        
        let public = self.key_pair.exit("Public key field necessary.").public.exit("Public key field necessary.");
        let public_key = Point::Point {
            x: get_biguint(&public.0, hex, le),
            y: get_biguint(&public.1, hex, le),
        };

        Signature::new(r, s, curve, public_key)
    }
}

fn get_name_toml(filename: &str) -> String{
    if ! filename.ends_with(".toml"){
        filename.to_owned() + ".toml"
    }else{
        filename.to_owned()
    }
    
}

pub fn to_toml<T:Serialize>(t: T, path: &str, new: bool){
    let path = get_name_toml(path);
    let mut file;
    if new{
        file = File::options().write(true).create_new(true).open(path).exit("Error while creating file.");
    }else{
        file = File::create(path).exit("Error while creating file.");
    }
    let content = toml::to_string(&t).exit("Error while parsing to toml.");
    file.write_all(content.as_bytes()).exit("Error while writing to the file.");
}

pub fn from_toml(path: &str) -> OutputTomlFile{
    let path = get_name_toml(path);
    let mut file = File::open(path).exit("Error while opening the file");
    let mut content = String::new();
    file.read_to_string(&mut content).exit("Error while reading the file.");
    toml::from_str(&content).exit("Error while parsing to toml.")
}
