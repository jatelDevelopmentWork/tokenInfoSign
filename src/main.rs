extern crate clap;
extern crate hex;
extern crate toml;
extern crate serde;
extern crate bitcoin_hashes;
extern crate secp256k1;


use clap::{Arg, App};
use bitcoin_hashes::{sha256, Hash};
use secp256k1::{Message, Secp256k1, SecretKey, SerializedSignature};
use std::mem::transmute;
use std::fs;
use std::io::prelude::*;

#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize, Debug)]
struct TokenDes {
    ticker: Option<String>,
    address: Option<String>,
    decimals : Option<u32>,
    chainId : Option<u32>,
    signedData: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Tokens
{
    tokens: Option<Vec<TokenDes>>
}


fn sign(one_token : & mut TokenDes) {
    let mut  hex_string = hex::encode(one_token.ticker.as_ref().unwrap());
    hex_string.push_str(&one_token.address.as_ref().unwrap());
    let decimals_bytes: [u8; 4] = unsafe { transmute(one_token.decimals.as_ref().unwrap().to_be()) };
    hex_string.push_str(&hex::encode(decimals_bytes));
    let chainId_bytes: [u8; 4] = unsafe { transmute(one_token.chainId.as_ref().unwrap().to_be()) };
    hex_string.push_str(&hex::encode(chainId_bytes));

    let se = signRaw(&hex_string);
    one_token.signedData = Some(hex::encode(se));
}

fn signRaw(raw: &str) -> SerializedSignature {
    let seckey = [0x57, 0xf1, 0xea, 0x4a, 0x7b, 0x2a, 0x13, 0xcc, 0x81, 0xa6, 0xe9, 0x10, 0xfd, 0x94, 0x46, 0x56, 0x92, 0x6e, 0xdd, 0x21, 0x93, 0xb6, 0x0f, 0x1d, 0x64, 0x07, 0x72, 0x70, 0x68, 0xcf, 0xe5, 0x95];
    let msg = hex::decode(raw).expect("Decoding failed");
    let secp = Secp256k1::new();
    let msg = sha256::Hash::hash(&msg);
    let msg = Message::from_slice(&msg).unwrap();
    println!("sha256 hash {:?}", msg);
    let seckey = SecretKey::from_slice(&seckey).unwrap();
    let signature =secp.sign(&msg, &seckey);
    let se = signature.serialize_der();
    println!("{:?}", hex::encode(se));
    return se;
}


fn main() {
    let matches = App::new("Token information secp256k1 signature tool")
                          .version("1.0")
                          .author("wanghengtao <wanghengtao@juzix.net>")
                          .about("ticker || address || number of decimals (uint4be) || chainId (uint4be) signed by the following secp256k1 private key 57f1ea4a7b2a13cc81a6e910fd944656926edd2193b60f1d6407727068cfe595")
                          .arg(Arg::with_name("config")
                               .short("c")
                               .long("config")
                               .value_name("FILE")
                               .help("token configuration file in toml format")
                               .takes_value(true))
                          .arg(Arg::with_name("rawHex")
                               .short("r")
                               .long("rawHex")
                               .value_name("Hexadecimal string")
                               .help("ticker || address || number of decimals (uint4be) || chainId (uint4be) hexadecimal string")
                               .takes_value(true))
                          .get_matches();

    let token_file = matches.value_of("config");
    match token_file {
        None => println!("No config file entered"),
        Some(s) => {
            println!("config file: {}", s);
            let mut file = match fs::File::open(s) {
                Ok(f) => f,
                Err(e) => panic!("no such file {} exception:{}", s, e)
            };
            let mut str_val = String::new();
            match file.read_to_string(&mut str_val) {
                Ok(s) => s
                ,
                Err(e) => panic!("Error Reading file: {}", e)
            };

            let all_token: Tokens = toml::from_str(&str_val).unwrap();
            let mut all_token_desc = all_token.tokens.unwrap();

            for one_token in & mut all_token_desc {
                sign(one_token);
            }

            let mut signed_token = Tokens{tokens: Some(all_token_desc)};
            str_val = toml::to_string(&signed_token).unwrap();

            println!("{:?}", str_val);

            fs::write(s, str_val.as_bytes()).expect("Unable to write data");

        }
    }

    let raw_hex = matches.value_of("rawHex");
    match raw_hex {
        None => println!("The string to be signed is not entered"),
        Some(s) => {
            println!("raw hex: {}", s);
            let result = signRaw(s);
            println!("Signed data: {:?}", hex::encode(result));
        }
    }
}
