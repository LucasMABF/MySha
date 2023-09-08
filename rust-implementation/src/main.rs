use clap::Parser;
use std::io::{self, IsTerminal, BufRead, Write};

mod helper_functions;
use helper_functions::*;

/// implementation of sha512 in rust, with animations, to understand the process
#[derive(Parser, Debug)]
#[command(name = "mysha")]
#[command(author = "Lucas")]
#[command(version = "0.0.42")]
struct Args{
    /// messages to be hashed, can also be passed through stdin with |
    messages: Vec<String>,

    /// Turn on animation
    #[arg(short, default_value_t = false)]
    animation: bool,

    /// Step through animation with enter
    #[arg(short, default_value_t = false)]
    enter: bool,
    
    /// Verbose output
    #[arg(short, default_value_t = false)]
    verbose: bool,

}

fn main() {
    // todo loading bar
    let args = Args::parse();
    let mut messages = args.messages;
    let mut animation = args.animation;
    let enter = args.enter;
    let verbose = args.verbose;
    
    if ! io::stdin().is_terminal(){
        let stdin = io::stdin().lock().lines();
        for line in stdin{
            messages.push(line.expect("Error while geting stdin passed."));
        }
    }

    if ! io::stdout().is_terminal(){
        animation = false;
    }

    if messages.len() == 0{
        print!("Message to hash:  ");
        std::io::stdout().flush().unwrap();
        let mut message = String::new();
        io::stdin().read_line(&mut message).expect("Error while geting user input");
        messages.push(message.trim().parse().expect("Error while parsing user input"));
    }


    for (index, message) in messages.into_iter().enumerate(){

        let mut bits = binary_handling::get_binary_message(message.clone());

        binary_handling::pad(&mut bits);

        let message_blocks = binary_handling::get_message_blocks(bits);

        let A = constants::initialize_a();

        let (mut a0, mut b0, mut c0, mut d0, mut e0, mut f0, mut g0, mut h0) = (A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7]);

        let K = constants::initialize_k();


        for block in message_blocks{
            let mut message_schedule = binary_handling::get_message_schedule(block);

            for i in 16..64{
                message_schedule.push(operations::addn(vec![operations::sigma1(message_schedule[i - 2]), message_schedule[i - 7], operations::sigma0(message_schedule[i - 15]), message_schedule[i - 16]]));
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (a0, b0, c0, d0, e0, f0, g0, h0);

            
            for (i, m) in message_schedule.iter().enumerate(){
                let t1 = operations::addn(vec![operations::SIGMA1(e), operations::choice(e, f, g), h, K[i], *m]);
                let t2 = operations::add(operations::SIGMA0(a), operations::majority(a, b, c));

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
        if verbose{
            print!("[{}]({:70}", index, message + "): ");

        }
        println!("{}", hash256);
    }

}
