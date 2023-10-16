use clap::{Parser, ValueEnum};
use std::io::{self, IsTerminal, BufRead, Write, Read};
use std::fs::File;

mod helper_functions;
use helper_functions::*;
mod animation;
use animation::*;

/// implementation of sha256 in rust, with animations, to understand the process
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

    /// Input Type
    #[arg(short, default_value_t = Type::Text, value_enum)]
    type_input: Type,

    /// Turn off separate by lines on stdin
    #[arg(short, default_value_t = false)]
    separate_by_line_disabled: bool,

}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Type{
    /// String to be hashed
    Text,
    /// Binary value to be hasehd
    Binary,
    /// File to be hashed
    File,
    /// Hexadecimal number
    Hex,
    /// Decimal number
    Decimal
}

fn main() {
    let args = Args::parse();
    let mut messages = args.messages;
    let mut animation = args.animation;
    let mut enter = args.enter;
    let verbose = args.verbose;
    let type_input = args.type_input;
    let s = args.separate_by_line_disabled;
    
    if ! io::stdin().is_terminal(){
        enter = false;
        wait(false, 1000);
        
        if s{
            let mut m = String::new();
            io::stdin().read_to_string(&mut m).expect("Error while geting stdin passed.");
            messages.push(m);

        }else{
            let stdin = io::stdin().lock().lines();
            for line in stdin{
                messages.push(line.expect("Error while geting stdin passed."));
            }
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

    if ! animation{

        for (index, message) in messages.iter().enumerate(){

            let mut bits = match type_input{
                Type::Binary => {
                    binary_handling::validate_bits(message);
                    message.to_string()
                },
                Type::Text => binary_handling::get_binary_message(message),
                Type::File => {
                    let mut file = File::open(message).expect("Error while oppening the file");
                    let mut content = String::new();
                    file.read_to_string(&mut content).expect("Error while reading the file");
                    
                    binary_handling::get_binary_message(&content)
                },
                Type::Hex => binary_handling::get_bits_hex(message),
                Type::Decimal => format!("{:b}", message.parse::<i32>().expect("Error while parsing number. Invalid inpput.")),
            };

            binary_handling::pad(&mut bits);

            let message_blocks = binary_handling::get_message_blocks(bits);

            let A = constants::initialize_a();

            let (mut a0, mut b0, mut c0, mut d0, mut e0, mut f0, mut g0, mut h0) = (A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7]);

            let K = constants::initialize_k();


            for block in message_blocks.iter(){
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
                print!("[{}]({:70}", index, message.to_owned() + "): ");

            }
            println!("{}", hash256);
        }
    }else{
        printf("\x1b[?1049h"); // create alternative buffer

        let mut hashes = Vec::new();
        for (index, message) in messages.iter().enumerate(){
            cleartop();
            if messages.len() != 1{
                printf("messages: [");
                for (i, m) in messages.iter().enumerate(){
                    if i  == messages.len() - 1{
                        if i != index{
                            printf(format!("{:?}]", m).as_str());
                        }else{
                            blink(format!("{:?}", m).as_str());
                            printf("]");
                        }
                    }else{
                        if i != index{
                            printf(format!("{:?}, ", m).as_str());
                        }else{
                            blink(format!("{:?}", m).as_str());
                            printf(", ");
                        }
                    }
                }
                wait(enter, 2000);
                printf(format!("\nmessage: {}", message).as_str());  
                wait(enter, 2000);
            }
            cleartop();
            if type_input == Type::Text{
                println!("message: {}", message);
                wait(enter, 2000);
            }
            
            let mut bits = match type_input{
                Type::Binary => {
                    binary_handling::validate_bits(message);
                    message.to_owned()
                },
                Type::Text => binary_handling::get_binary_message(message),
                Type::File => {
                    let mut file = File::open(message).expect("Error while oppening the file");
                    let mut content = String::new();
                    file.read_to_string(&mut content).expect("Error while reading the file");
                    
                    binary_handling::get_binary_message(&content)
                },
                Type::Hex => binary_handling::get_bits_hex(message),
                Type::Decimal => format!("{:b}", message.parse::<i32>().expect("Erro while parsing number. Invalid inpput.")),
            };

            printf(format!("bits: {}", bits).as_str());
            wait(enter, 2000);

            binary_handling_animated::pad(&mut bits);
            wait(enter, 1000);

            let message_blocks = binary_handling::get_message_blocks(bits);
            println!("message blocks: {:#?}", message_blocks);
            wait(enter, 1000);
            cleartop();

            if index == 0 {
                binary_handling_animated::animate_operations(enter);
                binary_handling_animated::animate_K(enter);
            }

            let mut A0 = constants::initialize_a();

            let K = constants::initialize_k();

            for (index_block, block) in message_blocks.iter().enumerate(){
                cleartop();
                if index_block > 0{
                    binary_handling_animated::keep_a(&A0);
                }
                let mut message_schedule = binary_handling_animated::get_message_schedule(block, index_block);


                printf("w16: ");
                printf("\x1b[34C");
                printf("= sigma1(t-2) + (t-7) + sigma0(t-15) + (t-16) % 2**32");
                wait(enter, 4000);



                for i in 16..64{
                    let new = operations::addn(vec![operations::sigma1(message_schedule[i - 2]), message_schedule[i - 7], operations::sigma0(message_schedule[i - 15]), message_schedule[i - 16]]);
                    message_schedule.push(new);

                    printf(format!("\x1b[16F\x1b[37C -> {:032b}", message_schedule[i - 16]).as_str());

                    printf(format!("\x1b[E\x1b[37C -> sigma0 = {:032b}", operations::sigma0(message_schedule[i - 15])).as_str());

                    printf(format!("\x1b[8E\x1b[37C -> {:032b}", message_schedule[i - 7]).as_str());

                    printf(format!("\x1b[5E\x1b[37C -> sigma1 = {:032b}", operations::sigma1(message_schedule[i - 2])).as_str());

                    printf("\x1b[2E");
                    
                    if i != 16{
                        for j in 1..17{
                            printf(format!("\x1b[Fw{:02}: {:032b}", i - j, message_schedule[i - j]).as_str());
                        }
                        printf("\x1b[16E");
                    }
                    

                    printf(format!("w{:02}: {:032b}", i, new).as_str());

                    wait(enter, 100);
                }
                wait(false, 500);

                cleartop();
                if index_block > 0{
                    binary_handling_animated::keep_a(&A0);
                }
                printf(format!("message block[{}]: {}\n", index_block, block).as_str());

                println!("\nCompression: \n");
                println!("W00: ");
                println!("K0: \n");
                println!("T1 =");
                println!("T2 = \n\n");
                
                if index_block == 0{
                    binary_handling_animated::animate_a(enter);
                    wait(enter, 300);
                    binary_handling_animated::save_a(&A0, enter);
                }else{
                    for i in 97..105 as u8{
                        println!("{} = ", i as char)
                    }
                    printf("\x1b[8F\x1b[4C");
                    wait(enter, 200);
                    binary_handling_animated::restore_a(&A0, enter, false);
                    printf("\x1b[8E")
                }
                wait(enter, 200);
                printf("\x1b[12F\x1b[4C SIGMA1(e) + choice(e, f, g) + h + K0");
                printf("\x1b[E\x1b[4C SIGMA0(a) + majority(a, b, c)\x1b[11E");
                
                wait(enter, 400);

                let mut A = A0.clone();

                for (i, m) in message_schedule.iter().enumerate(){
                    printf(format!("\x1b[15FW{:02}: {:032b}", i, m).as_str());
                    printf(format!("\x1b[EK{:02}: {:032b}\x1b[14E", i, K[i]).as_str());
                    wait(enter, 200);

                    let t1 = operations::addn(vec![operations::SIGMA1(A[4]), operations::choice(A[4], A[5], A[6]), A[7], K[i], *m]);
                    let t2 = operations::add(operations::SIGMA0(A[0]), operations::majority(A[0], A[1], A[2]));
                    printf(format!("\x1b[12F\x1b[42C = {:032b}", t1).as_str());
                    printf(format!("\x1b[E\x1b[42C = {:032b}\x1b[11E", t2).as_str());
                    wait(enter, 100);

                    for j in 0..8{
                        if j == 0{
                            printf("\x1b[8F\x1b[36C\u{2193}           \x1b[E");
                        }else{
                            printf("\x1b[36C\u{2193}           \x1b[E")
                        }
                    }
                    wait(enter, 200);

                    for j in 0..8{
                        if j == 7{
                            A[7 - j] = operations::add(t1, t2);
                            printf(format!("\x1b[F\x1b[4C{: >32} -> T1 + T2\x1b[8E", "").as_str());
                        }else if j == 3{
                            A[7 - j] = operations::add(A[7 - j - 1], t1);
                            printf(format!("\x1b[F\x1b[4C{:032b} + T1", A[7 - j - 1]).as_str());
                        }else{
                            printf(format!("\x1b[F\x1b[4C{:032b} ", A[7 - j - 1]).as_str());
                            A[7 - j] = A[7 - j - 1];
                        }
                    }
                    wait(enter, 200);

                    printf(format!("\x1b[4F\x1b[4C{:032b}", A[4]).as_str());
                    printf(format!("\x1b[4F\x1b[4C{:032b}\x1b[8E", A[0]).as_str());
                    wait(enter, 200);
                }

                for _ in 0..8{
                    printf("\x1b[F\x1b[36C +         \x1b[8D");
                }
                binary_handling_animated::restore_a(&A0, enter, true);
                wait(enter, 200);

                printf("\x1b[F\x1b[E");
                for k in 0..8{
                    A0[k] = operations::add(A[k], A0[k]);
                    printf(format!("\x1b[4C{:032b}{: >35}\x1b[E", A0[k], "").as_str());
                }
                wait(enter, 100);

                if message_blocks.len() == index_block + 1{
                    for j in A0.iter().rev(){
                        printf(format!("\x1b[F\x1b[36C = {:08x}", j).as_str());
                    }
                    printf("\x1b[8E\n");
                    wait(enter, 100);

                    let mut hash256 = String::new();
                    for (k, j) in A0.iter().enumerate(){
                        blink(format!("\x1b[{}F\x1b[39C{:08x}\x1b[{}E", 9 - k, j, 9 - k).as_str());
                        if k != 0{
                            printf(format!("\x1b[{}C{:08x}",k * 8, j).as_str());
                        }else{
                            printf(format!("{:08x}", j).as_str());
                        }
                        hash256 += &format!("{:08x}", j);
                        wait(enter,100);
                        printf(format!("\x1b[{}F\x1b[39C{:08x}\x1b[{}E", 9 - k, j, 9 - k).as_str());
                    }
                    hashes.push(hash256);
                    wait(enter, 1000);
                }else{
                    binary_handling_animated::save_a(&A0, enter);
                }
            }        
        }

        printf("\x1b[?1049l"); // disable alternative buffer, get back to previous state
        for (k, hash256) in hashes.iter().enumerate(){
            if verbose{
                print!("[{}]({:70}", k, messages[k].to_owned() + "): ");
            }
            println!("{}", hash256);
        }
    }

}
