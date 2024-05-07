pub mod binary_handling{
    use super::super::HashError;

    pub fn get_binary_message(message: &str) -> String{
        let bytes = message.to_owned().into_bytes();
        let mut bits = String::new();
        
        for byte in bytes{
            bits += format!("{:08b}", byte).as_ref();
        }

        bits
    }

    pub fn validate_bits(message: &str) -> Result<(), HashError>{
        for bit in message.chars(){
            if bit != '0' && bit != '1'{
                return Err(HashError::InvalidBinary);
            }
        }
        Ok(())
    }

    pub fn get_bits_hex(message: &str, le: bool) -> Result<String, HashError>{
        let mut bits = String::new();
        let mut message = String::from(message);
        if le{
            if message.len() % 2 != 0{
                return Err(HashError::NotWholeBytes);
            }
            message = (0..message.len()).step_by(2).rev().map(|i| &message[i..i+2]).collect();
        }
        for hex in message.chars(){
            bits += format!("{:04b}", u8::from_str_radix(hex.to_string().as_str(), 16).map_err(|_| HashError::InvalidHex)?).as_str();
        }
        
        Ok(bits)
    }

    pub fn pad(message: &mut String){
        let size = message.len();
        let size = format!("{:064b}", size);

        *message += "1";

        while (message.len() + 64) % 512 != 0{
            *message += "0";
        }

        *message += size.as_ref();
    }

    pub fn get_message_blocks(message: &str) -> Vec<String>{
        let mut message_blocks = Vec::new();

        for i in (0..message.len()).step_by(512){
            message_blocks.push(String::from(&message[i..i+512]));
        }


        message_blocks
    }

    pub fn get_message_schedule(block: &str) -> Vec<u32>{
        let mut message_schedule = Vec::new();

        for i in (0..block.len()).step_by(32){
            message_schedule.push(u32::from_str_radix(&block[i..i+32], 2).unwrap());
        }

        message_schedule

    }
}


pub mod operations{
    pub fn add(a: u32, b: u32) -> u32{
        let a:u64 = a as u64;
        let b:u64 = b as u64;
        let bits:u32 = ((a + b) % (2 as u64).pow(32)) as u32;
        bits
    }

    pub fn addn(nums: Vec<u32>) -> u32{
        let mut sum = 0;

        for num in nums{
            sum = add(sum, num);
        }

        sum

    }

    pub fn l_sigma0(bits: u32) -> u32{
        bits.rotate_right(7) ^ bits.rotate_right(18) ^ bits >> 3
    }

    pub fn l_sigma1(bits: u32) -> u32{
        bits.rotate_right(17) ^ bits.rotate_right(19) ^ bits >> 10
    }

    pub fn u_sigma0(bits: u32) -> u32{
        bits.rotate_right(2) ^ bits.rotate_right(13) ^ bits.rotate_right(22)
    }

    pub fn u_sigma1(bits: u32) -> u32{
        bits.rotate_right(6) ^ bits.rotate_right(11) ^ bits.rotate_right(25)
    }

    pub fn choice(a:u32, b:u32, c:u32) -> u32{
        let a = format!("{:032b}", a);
        let b = format!("{:032b}", b);
        let c = format!("{:032b}", c);
        let mut res = String::new();

        for ((ia, ib), ic) in a.chars().zip(b.chars()).zip(c.chars()){
            if ia == '1'{
                res.push(ib);
            }else {
                res.push(ic);
            }
        }

        u32::from_str_radix(&res, 2).unwrap()

    }

    pub fn majority(a:u32, b:u32, c:u32) -> u32{
        let a = format!("{:032b}", a);
        let b = format!("{:032b}", b);
        let c = format!("{:032b}", c);
        let mut res = String::new();

        for ((ia, ib), ic) in a.chars().zip(b.chars()).zip(c.chars()){
            if ia == ib{
                res.push(ia);
            }else{
                res.push(ic);
            }
        }

        u32::from_str_radix(&res, 2).unwrap()
    }

}


pub mod constants{
    pub fn get_primes(n: u8) -> Vec<f64>{
        let mut primes = Vec::new();
        primes.push(2 as f64);
        let mut i: f64 = 3.0;
        while primes.len() < n.into(){
            let mut is_prime = true;
            for j in &primes{
                if i % j == 0.0{
                    is_prime = false;
                    break;
                }
            }

            if is_prime{
                primes.push(i as f64);
            }

            i += 1.0;

        }

        primes
    }

    pub fn initialize_a() -> Vec<u32>{
        let mut a = Vec::new();
        let primes = get_primes(8);

        for i in primes{
            a.push(((i.sqrt() - i.sqrt().trunc()) * (2 as f64).powf(32.0)) as u32)
        }

        a

    }

    pub fn initialize_k() -> Vec<u32>{
        let mut k = Vec::new();
        let primes = get_primes(64);

        for i in primes{
            k.push(((i.cbrt() - i.cbrt().trunc()) * (2 as f64).powf(32.0)) as u32)
        }

        k
    }
}
