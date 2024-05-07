use clap::{Args, ValueEnum};
use std::io::{self, IsTerminal, BufRead, Write, Read};
use std::fs::File;
use mysha::sha256::{sha256, InputType, HashError, Hash256};

mod animation;
use animation::*;
mod helper_functions;
use helper_functions::*;

use crate::Exit;

#[derive(Args, Debug)]
pub struct HashArgs{
    /// messages to be hashed
    messages: Vec<String>,

    /// Turn on animation
    #[arg(short, long)]
    animation: bool,

    /// Step through animation with enter
    #[arg(short, long)]
    enter: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Input Type
    #[arg(short, long, default_value_t = Type::Text, value_enum)]
    r#type: Type,

    /// disables extra explanations on animation
    #[arg(short, long)]
    faster: bool,

    /// Turn off separate by lines on stdin passed by |
    #[arg(short, long)]
    separate_off: bool,

    /// Display output as little endian
    #[arg(short, long)]
    little_endian: bool,
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum Type{
    /// String
    Text,
    /// Binary value
    Binary,
    /// Little endian binary value
    LeBinary,
    /// File to be hashed
    File,
    /// Hexadecimal number
    Hex,
    /// Little endian hexadecimal number
    LeHex,
    /// Decimal number
    Decimal
}

pub fn hash(args: HashArgs) {
    let mut messages = args.messages;
    let mut animation = args.animation;
    let mut enter = args.enter;
    let verbose = args.verbose;
    let type_input = args.r#type;
    let s = args.separate_off;
    let f = args.faster;
    let le = args.little_endian;
    
    if ! io::stdin().is_terminal(){
        enter = false;
        
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
        io::stdin().read_line(&mut message).expect("Error while getting user input");
        messages.push(message.replace(['\n', '\r'], ""));
    }

    if ! animation{

        for (index_message, message) in messages.iter().enumerate(){

            let hash = match type_input{
                Type::Binary => sha256(message, InputType::Binary).exit("Error while parsing binary value. invalid binary input."),
                Type::LeBinary => sha256(message, InputType::LeBinary).exit("Error while parsing little endian binary value."),
                Type::Text => sha256(message, InputType::Text).unwrap(),
                Type::File => sha256(message, InputType::File).exit("Error while oppening the file."),
                Type::Hex => sha256(message, InputType::Hex).exit("Error while parsing hexadecimal value. Invalid Hex input."),
                Type::LeHex => sha256(message, InputType::LeHex).exit("Error while parsing little endian hexadecimal value."),
                Type::Decimal => sha256(message, InputType::Decimal).unwrap_or_else(|err| {
                    match err{
                        HashError::DecimalTooBig => eprintln!("Error while parsing number. Number is too big, try using type hex."),
                        _ => eprintln!("Error while parsing number. Invalid input."),
                    };
                    std::process::exit(1);
                }),
            };

            if verbose{
                print!("[{}]({:70}", index_message, message.to_owned() + "): ");

            }
            if le{
                println!("{}", hash.get_hex_le());
            }else{
                println!("{}", hash);
            }
        }
    }else{
        ctrlc::set_handler(|| {
            printf("\x1b[m\x1b[?25h"); // make cursor visible
            printf("\x1b[?1049l"); // disable alternative buffer, get back to previous state
            std::process::exit(0);
        }).expect("Error initializing program");

        printf("\x1b[?1049h"); // create alternative buffer
        printf("\x1b[?25l"); // make cursor invisible

        let mut hashes = Vec::new();
        for (index_message, message) in messages.iter().enumerate(){
            cleartop();
            if messages.len() != 1{
                printf("messages: [");
                for (i, m) in messages.iter().enumerate(){
                    if i  == messages.len() - 1{
                        if i != index_message{
                            printf(format!("{:?}]", m).as_str());
                        }else{
                            blink(format!("{:?}", m).as_str());
                            printf("]");
                        }
                    }else{
                        if i != index_message{
                            printf(format!("{:?}, ", m).as_str());
                        }else{
                            blink(format!("{:?}", m).as_str());
                            printf(", ");
                        }
                    }
                }
                wait(enter, 2000);
                printf(format!("\nmessage: {}", message).as_str());  
                wait(enter, 1000);
            }
            cleartop();
            if type_input == Type::Text{
                println!("message: {}", message);
                wait(enter, 1000);
            }else if type_input == Type::Hex{
                println!("Hex value: {}", message);
                wait(enter, 1000);
            }else if type_input == Type::LeHex{
                println!("Little endian hex value: {}", message);
                wait(enter, 1000);
            }else if type_input == Type::Decimal{
                println!("Decimal value: {}", message);
                wait(enter, 1000);
            }else if type_input == Type::LeBinary{
                println!("Little endian binary value: {}", message);
                wait(enter, 1000);
            }
            
            let mut bits = match type_input{
                Type::Binary => {
                    binary_handling::validate_bits(message).exit("\x1b[m\x1b[?25h\x1b[?1049lError while parsing binary value. invalid binary input.");
                    message.to_owned()
                },
                Type::LeBinary => {
                    binary_handling:: validate_bits(message).exit("\x1b[m\x1b[?25h\x1b[?1049lError while parsing binary value. invalid binary input.");
                    if message.len() % 8 != 0{
                        Err::<Hash256, HashError>(HashError::NotWholeBytes).exit("\x1b[m\x1b[?25h\x1b[?1049lError while parsing binary value.");
                    }
                    (0..message.len()).step_by(8).rev().map(|i| &message[i..i+8]).collect()
                }
                Type::Text => binary_handling::get_binary_message(message),
                Type::File => {
                    let mut file = File::open(message).exit("\x1b[m\x1b[?25h\x1b[?1049lError while oppening the file.");
                    let mut content = String::new();
                    file.read_to_string(&mut content).exit("Error while reading the file");
                    
                    binary_handling::get_binary_message(&content)
                },
                Type::Hex => binary_handling::get_bits_hex(message, false).exit("\x1b[m\x1b[?25h\x1b[?1049lError while parsing hexadecimal value."),
                Type::LeHex => binary_handling::get_bits_hex(message, true).exit("\x1b[m\x1b[?25h\x1b[?1049lError while parsing hexadecimal value."),
                Type::Decimal => format!("{:b}", message.parse::<i128>().unwrap_or_else(|err| {
                    printf("\x1b[m\x1b[?25h"); // make cursor visible
                    printf("\x1b[?1049l"); // disable alternative buffer, get back to previous state
                    match err.kind(){
                        std::num::IntErrorKind::PosOverflow => eprintln!("Error while parsing number. Number is too big, try using type hex."),
                        _ => eprintln!("Error while parsing number. Invalid input."),
                    };
                    std::process::exit(1);
                })),
            };

            printf(format!("bits: {}", bits).as_str());
            wait(enter, 1000);

            binary_handling_animated::pad(&mut bits);
            wait(enter, 1000);

            let message_blocks = binary_handling::get_message_blocks(&bits);

            println!("\nmessage blocks: [");
            wait(enter, 500);
            for (j, i) in message_blocks.iter().enumerate(){
                printf("\x1b[H");
                if type_input == Type::Text{
                    println!("message: {}", message);
                }else if type_input == Type::Hex{
                    println!("Hex value: {}", message);
                }else if type_input == Type::LeHex{
                    println!("Little endian hex value: {}", message);
                }else if type_input == Type::Decimal{
                    println!("Decimal value: {}", message);
                }else if type_input == Type::LeBinary{
                    println!("Little endian binary value: {}", message);
                }
                printf(format!("bits: {}", &bits[0..j * 512]).as_str());
                blink(format!("{}", &bits[j * 512..(j * 512) + 512]).as_str());
                printf(format!("{}\n\n\n", &bits[(j * 512) + 512..]).as_str());
                
                for k in 0..j + 1{
                    if k == j{
                        blink(format!("    {:#?},\n", i).as_str());
                    }else{
                        printf(format!("    {:#?},\n", message_blocks[k]).as_str());
                    }
                }

                wait(enter, 1000);
            }
            printf("\x1b[H");
            if type_input == Type::Text{
                println!("message: {}", message);
            }else if type_input == Type::Hex{
                println!("Hex value: {}", message);
            }else if type_input == Type::LeHex{
                println!("Little endian hex value: {}", message);
            }else if type_input == Type::Decimal{
                println!("Decimal value: {}", message);
            }else if type_input == Type::LeBinary{
                println!("Little endian binary value: {}", message);
            }
            println!("bits: {}", bits);
            println!("\x1b[Emessage blocks: {:#?}", message_blocks);
            
            wait(enter, 1000);
            cleartop();

            if index_message == 0 && !f{
                binary_handling_animated::animate_operations(enter);
                binary_handling_animated::animate_k(enter);
            }

            let mut a0 = constants::initialize_a();

            let k = constants::initialize_k();

            for (index_block, block) in message_blocks.iter().enumerate(){
                cleartop();
                if index_block > 0{
                    binary_handling_animated::keep_a(&a0);
                }
                let mut message_schedule = binary_handling_animated::get_message_schedule(enter, block, index_block);


                printf("w16: ");
                printf("\x1b[34C");
                printf("= sigma1(t-2) + (t-7) + sigma0(t-15) + (t-16) (mod 2**32)");
                wait(enter, 2000);



                for i in 16..64{
                    let new = operations::addn(vec![operations::l_sigma1(message_schedule[i - 2]), message_schedule[i - 7], operations::l_sigma0(message_schedule[i - 15]), message_schedule[i - 16]]);
                    message_schedule.push(new);

                    printf(format!("\x1b[16F\x1b[37C -> {:032b}", message_schedule[i - 16]).as_str());

                    printf(format!("\x1b[E\x1b[37C -> sigma0 = {:032b}", operations::l_sigma0(message_schedule[i - 15])).as_str());

                    printf(format!("\x1b[8E\x1b[37C -> {:032b}", message_schedule[i - 7]).as_str());

                    printf(format!("\x1b[5E\x1b[37C -> sigma1 = {:032b}", operations::l_sigma1(message_schedule[i - 2])).as_str());

                    printf("\x1b[2E");
                    
                    if i != 16{
                        for j in 1..17{
                            printf(format!("\x1b[Fw{:02}: {:032b}", i - j, message_schedule[i - j]).as_str());
                        }
                        printf("\x1b[16E");
                    }
                    

                    printf(format!("w{:02}: {:032b}", i, new).as_str());

                    wait(enter, 350);
                }
                wait(false, 1000);

                cleartop();
                if index_block > 0{
                    binary_handling_animated::keep_a(&a0);
                }
                printf(format!("message block[{}]: {}\n", index_block, block).as_str());

                println!("\nCompression: \n");
                println!("W00: ");
                println!("K00: \n");
                println!("T1 =");
                println!("T2 = \n\n");
                
                if index_block == 0{
                    binary_handling_animated::animate_a(enter);
                    wait(enter, 500);
                    binary_handling_animated::save_a(&a0, enter);
                }else{
                    for i in 97..105 as u8{
                        println!("{} = ", i as char)
                    }
                    printf("\x1b[8F\x1b[4C");
                    wait(enter, 500);
                    binary_handling_animated::restore_a(&a0, enter, false);
                    printf("\x1b[8E")
                }
                wait(enter, 400);
                printf("\x1b[12F\x1b[4C SIGMA1(e) + choice(e, f, g) + h + K00 + W00 (mod 2**32)");
                printf("\x1b[E\x1b[4C SIGMA0(a) + majority(a, b, c) (mod 2**32)\x1b[11E");
                
                wait(enter, 1000);

                let mut a = a0.clone();

                for (i, m) in message_schedule.iter().enumerate(){
                    printf(format!("\x1b[15FW{:02}: {:032b}", i, m).as_str());
                    printf(format!("\x1b[EK{:02}: {:032b}", i, k[i]).as_str());
                    printf(format!("\x1b[2E\x1b[40C{:02} + W{:02}\x1b[12E", i, i).as_str());
                    if i < 3{
                        wait(enter, 1000);
                    }else{
                        wait(enter, 200);
                    }

                    let t1 = operations::addn(vec![operations::u_sigma1(a[4]), operations::choice(a[4], a[5], a[6]), a[7], k[i], *m]);
                    let t2 = operations::add(operations::u_sigma0(a[0]), operations::majority(a[0], a[1], a[2]));
                    printf(format!("\x1b[12F\x1b[61C = {:032b}", t1).as_str());
                    printf(format!("\x1b[E\x1b[61C = {:032b}\x1b[11E", t2).as_str());
                    if i < 3{
                        wait(enter, 1000);
                    }else{
                        wait(enter, 200);
                    }

                    for j in 0..8{
                        if j == 0{
                            printf("\x1b[8F\x1b[36C\u{2193}           \x1b[E");
                        }else{
                            printf("\x1b[36C\u{2193}           \x1b[E")
                        }
                    }
                    if i < 3{
                        wait(enter, 1000);
                    }else{
                        wait(enter, 200);
                    }

                    for j in 0..8{
                        if j == 7{
                            a[7 - j] = operations::add(t1, t2);
                            printf(format!("\x1b[F\x1b[4C{: >32} -> T1 + T2\x1b[8E", "").as_str());
                        }else if j == 3{
                            a[7 - j] = operations::add(a[7 - j - 1], t1);
                            printf(format!("\x1b[F\x1b[4C{:032b} + T1", a[7 - j - 1]).as_str());
                        }else{
                            printf(format!("\x1b[F\x1b[4C{:032b} ", a[7 - j - 1]).as_str());
                            a[7 - j] = a[7 - j - 1];
                        }
                    }
                    if i < 3{
                        wait(enter, 1000);
                    }else{
                        wait(enter, 200);
                    }

                    printf(format!("\x1b[4F\x1b[4C{:032b}", a[4]).as_str());
                    printf(format!("\x1b[4F\x1b[4C{:032b}\x1b[8E", a[0]).as_str());
                    if i < 3{
                        wait(enter, 1000);
                    }else{
                        wait(enter, 200);
                    }
                }

                for _ in 0..8{
                    printf("\x1b[F\x1b[36C +         \x1b[8D");
                }
                wait(enter, 1000);
                binary_handling_animated::restore_a(&a0, enter, true);
                wait(enter, 1000);

                printf("\x1b[F\x1b[E");
                for k in 0..8{
                    a0[k] = operations::add(a[k], a0[k]);
                    printf(format!("\x1b[4C{:032b}{: >47}\x1b[E", a0[k], "").as_str());
                }
                wait(enter, 800);

                if message_blocks.len() == index_block + 1{
                    for i in a0.iter().rev(){
                        printf(format!("\x1b[F\x1b[36C = {:08x}", i).as_str());
                    }
                    printf("\x1b[8E\n");
                    wait(enter, 500);

                    printf("hash:");
                    wait(enter, 200);
                    let mut hash256 = String::new();
                    for (i, j) in a0.iter().enumerate(){
                        blink(format!("\x1b[{}F\x1b[39C{:08x}\x1b[{}E", 9 - i, j, 9 - i).as_str());
                        if i != 0{
                            printf(format!("hash: \x1b[{}C{:08x}", i * 8, j).as_str());
                        }else{
                            printf(format!("hash: {:08x}", j).as_str());
                        }
                        hash256 += &format!("{:08x}", j);
                        wait(enter,500);
                        printf(format!("\x1b[{}F\x1b[39C{:08x}\x1b[{}E", 9 - i, j, 9 - i).as_str());
                    }
                    if le{
                        printf("\n\nle hex: ");
                        wait(enter, 200);
                        hash256 = (0..hash256.len()).step_by(2).rev().map(|i|{
                            printf(&format!("\x1b[2Fhash: {}", &hash256[0..i]));
                            blink(&hash256[i..i+2]);
                            printf(&hash256[i+2..]);
                            printf(&format!("\x1b[2Ele hex:\x1b[{}C{}",1 + hash256.len() - i - 2, &hash256[i..i+2]));
                            wait(enter, 500);
                            &hash256[i..i+2]
                        }).collect();
                        printf(&format!("\x1b[2Fhash: {}", &hash256[hash256.len()-2..]));
                    }

                    hashes.push(hash256);
                    wait(enter, 1000);
                }else{
                    binary_handling_animated::save_a(&a0, enter);
                }
            }        
        }

        printf("\x1b[?25h"); // make cursor visible
        printf("\x1b[?1049l"); // disable alternative buffer, get back to previous state
        for (i, hash256) in hashes.iter().enumerate(){
            if verbose{
                print!("[{}]({:70}", i, messages[i].to_owned() + "): ");
            }
            println!("{}", hash256);
        }
    }

}
