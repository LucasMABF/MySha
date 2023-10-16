use std::io::{self, Write, stdout};
use std::{thread, time::Duration};

pub fn printf(m: &str){
    print!("{}", m);
    stdout().flush().unwrap();
}

pub fn clear(){
    printf("\x1b[2J");
}

pub fn top(){
    printf("\x1b[H"); // cursor on 1, 1
}

pub fn cleartop(){
    clear();
    top();
}

pub fn blink(m: &str){
    printf(format!("\x1b[5m\x1b[4m\x1b[36m{}\x1b[m", m).as_str())
}

pub fn wait(enter: bool, time: u64){
    if enter{
        let mut s = String::new();
        printf("\x1b7");
        printf("\x1b[1000E");
        printf("\x1b[F\x1b[1000C\x1b[15DPress Enter");
        io::stdin().read_line(&mut s).expect("Error while waiting Enter");
        if s != "\r\n"{
            panic!("You are not supposed to write anything, so the animation will work propperly. just press enter");
        }
        printf("\x1b[F\x1b[1000C\x1b[15D\x1b[0J");
        printf("\x1b8");
    }else{
        thread::sleep(Duration::from_millis(time));
    }
}

pub mod binary_handling_animated{
    use crate::helper_functions;

    use super::{printf, wait, blink, cleartop, top};

    pub fn pad(message: &mut String){
        let size = message.len();
        let size = format!("{:064b}", size);

        *message += "1";
        printf("\x1b[32m1\x1b[m");
        wait(false, 200);

        printf("\x1b[33m");
        while (message.len() + 64) % 512 != 0{
            *message += "0";
            printf("0");
            wait(false, 10);

        }
        printf("\x1b[m");

        *message += size.as_str();
        printf("\x1b[36m");
        printf(format!("{}", size).as_str());
        printf("\x1b[m\n");
        wait(false, 500);

    }

    pub fn get_message_schedule(block: &str, index: usize) -> Vec<u32>{
        let mut message_schedule = Vec::new();

        printf(format!("message block[{}]: {}", index, &block).as_str());
        wait(false, 1000);

        for i in (0..block.len()).step_by(32){
            top();
            let n = u32::from_str_radix(&block[i..i+32], 2).unwrap();
            message_schedule.push(n);

            printf(format!("message block[{}]: {}", index, &block[0..i]).as_str());
            blink(&block[i..i+32]);
            println!("{}\n", &block[i+32..]);


            println!("message schedule: \n");

            for j in 0..16{
                if j < (i / 32){
                    println!("w{:02}: {:032b}", j, message_schedule[j]);
                }else if j == (i / 32){
                    printf(format!("w{:02}: ", j).as_str());
                    blink(format!("{:032b}\n", n).as_str());
                }else{
                    println!("w{:02}: ", j);
                }
            }
            wait(false, 400);

        }

        printf("\x1b7");
        printf(format!("\x1b[F\x1b[2Kw15: {:032b}", message_schedule[15]).as_str());
        printf(format!("\x1b[Hmessage block[{}]: {}", index, block).as_str());
        printf("\x1b8");
        message_schedule
    }

    pub fn rotr(mut n: u32, rot: u32) -> u32{
        for _ in 0..rot{
            n = n.rotate_right(1);
            printf(format!("{:032b}", n).as_str());
            wait(false, 200);
            printf("\x1b[32D")
        }
        n
    }

    pub fn shr(mut n: u32, sh: u32) -> u32{
        for _ in 0..sh{
            n = n >> 1;
            printf(format!("{:032b}", n).as_str());
            wait(false, 100);
            printf("\x1b[32D");
        }
        n
    }

    pub fn xor(n1: u32, n2: u32, n3: u32){
        let result = format!("{:032b}", (n1 ^ n2 ^ n3));
        for i in 0..33{
            printf(format!("{:>32}", &result[(32 - i)..]).as_str());
            wait(false, 200);
            printf("\x1b[32D");
        }
    }

    pub fn sigma0(enter: bool, sample: &str){
        println!("sigma 0\n");
        println!("x      : {}", sample);
        println!("{:->41}", "");
        println!("ROTR 7 : {}", sample);
        println!("ROTR 18: {}", sample);
        println!("SHR 3  : {}", sample);
        wait(enter, 200);
        printf("\x1b[3A\x1b[9C");
        let n1 = rotr(u32::from_str_radix(sample, 2).unwrap(), 7);
        wait(enter, 200);
        printf("\x1b[B");
        let n2 = rotr(u32::from_str_radix(sample, 2).unwrap(), 18);
        printf("\x1b[B");
        wait(enter, 200);
        let n3 = shr(u32::from_str_radix(sample, 2).unwrap(), 3);
        wait(enter, 200);
        printf("\x1b[A\x1b[32C XOR");
        printf("\x1b[B\x1b[4D XOR\n");
        println!("{: >9}{:->32}", "", "");
        print!("{: >9}", "");
        wait(enter, 200);
        xor(n1, n2, n3);
        wait(enter, 500);
        cleartop();
    }

    pub fn sigma1(enter: bool, sample: &str){
        println!("sigma 1\n");
        println!("x      : {}", sample);
        println!("{:->41}", "");
        println!("ROTR 17: {}", sample);
        println!("ROTR 19: {}", sample);
        println!("SHR 10 : {}", sample);
        wait(enter, 200);
        printf("\x1b[3A\x1b[9C");
        let n1 = rotr(u32::from_str_radix(sample, 2).unwrap(), 17);
        wait(enter, 200);
        printf("\x1b[B");
        let n2 = rotr(u32::from_str_radix(sample, 2).unwrap(), 19);
        printf("\x1b[B");
        wait(enter, 200);
        let n3 = shr(u32::from_str_radix(sample, 2).unwrap(), 10);
        wait(enter, 200);
        printf("\x1b[A\x1b[32C XOR");
        printf("\x1b[B\x1b[4D XOR\n");
        println!("{: >9}{:->32}", "", "");
        print!("{: >9}", "");
        wait(enter, 200);
        xor(n1, n2, n3);
        wait(enter, 500);
        cleartop();
    }

    pub fn SIGMA0(enter: bool, sample: &str){
        println!("SIGMA 0\n");
        println!("x      : {}", sample);
        println!("{:->41}", "");
        println!("ROTR 2 : {}", sample);
        println!("ROTR 13: {}", sample);
        println!("ROTR 22: {}", sample);
        wait(enter, 200);
        printf("\x1b[3A\x1b[9C");
        let n1 = rotr(u32::from_str_radix(sample, 2).unwrap(), 2);
        wait(enter, 200);
        printf("\x1b[B");
        let n2 = rotr(u32::from_str_radix(sample, 2).unwrap(), 13);
        printf("\x1b[B");
        wait(enter, 200);
        let n3 = rotr(u32::from_str_radix(sample, 2).unwrap(), 22);
        wait(enter, 200);
        printf("\x1b[A\x1b[32C XOR");
        printf("\x1b[B\x1b[4D XOR\n");
        println!("{: >9}{:->32}", "", "");
        print!("{: >9}", "");
        wait(enter, 200);
        xor(n1, n2, n3);
        wait(enter, 500);
        cleartop();
    }
    
    pub fn SIGMA1(enter: bool, sample: &str){
        println!("SIGMA 1\n");
        println!("x      : {}", sample);
        println!("{:->41}", "");
        println!("ROTR 6 : {}", sample);
        println!("ROTR 11: {}", sample);
        println!("ROTR 25: {}", sample);
        wait(enter, 200);
        printf("\x1b[3A\x1b[9C");
        let n1 = rotr(u32::from_str_radix(sample, 2).unwrap(), 6);
        wait(enter, 200);
        printf("\x1b[B");
        let n2 = rotr(u32::from_str_radix(sample, 2).unwrap(), 11);
        printf("\x1b[B");
        wait(enter, 200);
        let n3 = rotr(u32::from_str_radix(sample, 2).unwrap(), 25);
        wait(enter, 200);
        printf("\x1b[A\x1b[32C XOR");
        printf("\x1b[B\x1b[4D XOR\n");
        println!("{: >9}{:->32}", "", "");
        print!("{: >9}", "");
        wait(enter, 200);
        xor(n1, n2, n3);
        wait(enter, 500);
        cleartop();
    }

    pub fn choice(enter: bool, sample1: &str, sample2: &str, sample3: &str){
        println!("choice\n\n");
        println!("x: {}", sample1);
        println!("y: {}", sample2);
        println!("z: {}", sample3);
        println!("{:->35}", "");
        wait(enter, 200);
        for i in 0..32{
            printf(format!("\x1b[5F\x1b[{}C\u{2193}\x1b[0K", (31 - i) + 3).as_str());
            if &sample1[(31 - i)..(32 - i)] == "1"{
                printf("\x1b[2E\x1b[36C\u{2190}\x1b[B\x1b[D\x1b[0K\x1b[2E");
                printf(format!("\x1b[{}C{}", (31 - i) + 3, &sample2[(31 - i)..(32 - i)]).as_str());
            }else{
                printf("\x1b[3E\x1b[36C\u{2190}\x1b[A\x1b[D\x1b[0K\x1b[3E");
                printf(format!("\x1b[{}C{}", (31 - i) + 3, &sample3[(31 - i)..(32 - i)]).as_str());

            }
            wait(enter, 200);
        }
        cleartop();

    }

    pub fn majority(enter: bool, sample1: &str, sample2: &str, sample3: &str){
        println!("majority\n\n");
        println!("x: {}", sample1);
        println!("y: {}", sample2);
        println!("z: {}", sample3);
        println!("{:->35}", "");
        wait(enter, 200);
        for i in 0..32{
            printf(format!("\x1b[5F\x1b[{}C\u{2193}\x1b[0K\x1b[5E", (31 - i) + 3).as_str());
            if &sample1[(31 - i)..(32 - i)] == &sample2[(31 - i)..(32 - i)]{
                printf(format!("\x1b[{}C{}", (31 - i) + 3, &sample1[(31 - i)..(32 - i)]).as_str());
            }else{
                printf(format!("\x1b[{}C{}", (31 - i) + 3, &sample3[(31 - i)..(32 - i)]).as_str());

            }
            wait(enter, 200);
        }
        cleartop();
    }

    pub fn animate_operations(enter: bool){
        cleartop();
        println!("Operations\n");
        wait(enter, 100);
        let sample = "00000000111111110000000011111111";
        
        sigma0(enter, sample);

        sigma1(enter, sample);

        SIGMA0(enter, sample);

        SIGMA1(enter, sample);

        let sample1 = "00000000000000001111111111111111";
        let sample2 = "11111111111111110000000000000000";

        choice(enter, sample, sample1, sample2);
        
        majority(enter, sample, sample1, sample2);
    }

    pub fn animate_a(enter: bool){
        let primes = helper_functions::constants::get_primes(8);
        for i in 0..8{
            println!("{} = \u{221a}{}", (i as u8 + 97) as char, primes[i]);
        }
        wait(enter, 1000);
        printf("\x1b[8F");
        for i in 0..8{
            printf("\x1b[2K");
            println!("{} = {:.10}", (i as u8 + 97) as char, primes[i].sqrt());
        }
        wait(enter, 1000);
        printf("\x1b[8F");
        for i in 0..8{
            printf("\x1b[2K");
            println!("{} = {:.10} * 2**32", (i as u8 + 97) as char, primes[i].sqrt() - primes[i as usize].sqrt().trunc());
        }
        wait(enter, 1000);
        printf("\x1b[8F");
        for i in 0..8{
            printf("\x1b[2K");
            println!("{} = {}", (i as u8 + 97) as char, ((primes[i].sqrt() - primes[i].sqrt().trunc()) * (2 as f64).powf(32.0)) as u32);
        }
        wait(enter, 1000);
        printf("\x1b[8F");
        for i in 0..8{
            printf("\x1b[2K");
            println!("{} = {:032b}", (i as u8 + 97) as char, ((primes[i].sqrt() - primes[i].sqrt().trunc()) * (2 as f64).powf(32.0)) as u32);
        }
    }

    pub fn animate_K(enter: bool){
        println!("Constants K\n");
        println!("{:->12}", "");
        
        let primes = helper_functions::constants::get_primes(64);

        for i in 0..68{
            if i < 64{
                printf(format!("K{:02}: \u{221b}{}", i, primes[i]).as_str());
            }
            
            printf("\x1b7");
            if i as i8 - 1 >= 0 && i as i8 - 1 < 64{
                printf(format!("\x1b[F\x1b[5C{:.10}\x1b[0K", primes[i - 1].cbrt()).as_str());

            }
            if i as i8 - 2 >= 0 && i as i8 - 2 < 64{
                printf(format!("\x1b[F\x1b[5C{:.10} * 2**32\x1b[0K", (primes[i - 2].cbrt() - primes[i - 2].cbrt().trunc())).as_str());
            }
            if i as i8 - 3 >= 0 && i as i8 - 3 < 64{
                printf(format!("\x1b[F\x1b[5C{}\x1b[0K", ((primes[i - 3].cbrt() - primes[i - 3].cbrt().trunc()) * (2 as f64).powf(32.0)) as u32).as_str());

            }
            if i as i8 - 4 >= 0 && i as i8 - 4 < 64{
                printf(format!("\x1b[F\x1b[5C{:032b}\x1b[0K", ((primes[i - 4].cbrt() - primes[i - 4].cbrt().trunc()) * (2 as f64).powf(32.0)) as u32).as_str());
            }

            printf("\x1b8");
            if i < 64{
                println!();
            }
            wait(enter, 100);
        }
    }

    pub fn save_a(A: &Vec<u32>, enter: bool){
        for a in A.iter().rev(){
            blink(format!("\x1b[F\x1b[4C{:032b}", a).as_str());
        }
        wait(enter, 200);

        printf("\x1b[1000C\x1b[36D");

        for (k, a) in A.iter().enumerate(){
            blink(format!("{} = {:032b}\x1b[B\x1b[36D", (k as u8 + 97) as char, a).as_str());
        }
        wait(enter, 400);
        printf("\x1b[8A");

        for (k, a) in A.iter().enumerate(){
            printf(format!("{} = {:032b}\x1b[B\x1b[36D", (k as u8 + 97) as char, a).as_str());
        }

        for a in A.iter().rev(){
            printf(format!("\x1b[F\x1b[4C{:032b}", a).as_str());
        }
        printf("\x1b[8E");
    }

    pub fn restore_a(A: &Vec<u32>, enter:bool, erase:bool){
        printf("\x1b7");

        printf("\x1b[1000C\x1b[36D");
        for (k, a) in A.iter().enumerate(){
            blink(format!("{} = {:032b}\x1b[B\x1b[36D", (k as u8 + 97) as char, a).as_str());
        }
        printf("\x1b8");
        wait(enter, 200);

        for a in A.iter(){
            blink(format!("{:032b}\x1b[B\x1b[32D", a).as_str());
        }
        printf("\x1b8");
        wait(enter, 400);
        
        if erase{
            for a in A.iter(){
                printf(format!("\x1b[0K{:032b}\x1b[B\x1b[32D", a).as_str());
            }
        }else{

            for a in A.iter(){
                printf(format!("{:032b}\x1b[B\x1b[32D", a).as_str());
            }
            printf("\x1b8");

            printf("\x1b[1000C\x1b[36D");
            for (k, a) in A.iter().enumerate(){
                printf(format!("{} = {:032b}\x1b[B\x1b[36D", (k as u8 + 97) as char, a).as_str());
            }
        }

        printf("\x1b8");
    }

    pub fn keep_a(A: &Vec<u32>){
        printf("\x1b7\x1b[0H");

        printf(format!("{: >530}\x1b[11E\x1b[1000C\x1b[36D", "").as_str());

        for (k, a) in A.iter().enumerate(){
            printf(format!("{} = {:032b}\x1b[B\x1b[36D", (k as u8 + 97) as char, a).as_str());
        }

        printf("\x1b8")
    }


}
