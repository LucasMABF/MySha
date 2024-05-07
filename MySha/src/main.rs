use std::fmt::Display;

use clap::{Parser, Subcommand};

mod sha256_cli;
use sha256_cli::*;
mod ecc_cli;
use ecc_cli::*;

/// my implementations of different cryptography tools in rust
#[derive(Parser, Debug)]
#[command(name = "mysha")]
#[command(author = "Lucas")]
#[command(version = "0.0.42")]
struct Args{
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command{
    /// sha256, with animations
    Sha256(HashArgs),
    /// Elliptic Curve Cryptography tool
    Ecc(ECCArgs), 
}

fn main(){
    let args = Args::parse();

    match args.command{
        Command::Sha256(args) =>{
            hash(args);
        },
        Command::Ecc(args) =>{
            key_pair(args);
        }
    }
}

trait Exit{
    type Output;

    fn exit(self, msg: &str) -> Self::Output;
}

impl<T, E: Display> Exit for Result<T, E>{
    type Output = T;
    fn exit(self, msg: &str) -> T{
        match self{
            Err(e) =>{
                eprintln!("{} Error: {}", msg, e);
                std::process::exit(1);
            },
            Ok(t) => t,
        }
    }
}

impl<T> Exit for Option<T>{
    type Output = T;
    fn exit(self, msg: &str) -> T{
        match self{
            None => {
                eprintln!("{}", msg);
                std::process::exit(1);
            },
            Some(t) => t,
        }
    }
}