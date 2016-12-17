
extern crate crypto;
extern crate rand;

use self::crypto::pbkdf2::pbkdf2;
use std::iter::repeat;
use self::crypto::hmac::Hmac;
use self::crypto::sha1::Sha1;
use self::errors::{Result, ErrorKind};
use self::rand::{Rng, OsRng};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result::{Result as StdResult};
use std;

mod errors;

/// ! `rncryptor-rs` is a pure Rust implementation of
/// ! the [RNCryptor](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
/// ! V3 format by Rob Napier.

#[derive (Debug)]
pub struct EncryptionKey<'a>(&'a [u8;32]);

#[derive (Debug)]
pub struct Salt(pub [u8;8]);

impl Salt {
    pub fn new() -> Result<Salt> {
        match random_data_of_len(8) {
            Err(e) => Err(errors::Error::new(ErrorKind::SaltGenerationFailed(e), "Salt Generation failed.".to_owned())),
            Ok(v) => Ok(Salt(*array_ref!(v, 0,8)))
        }
    }
}

#[derive (Debug, PartialEq, Eq)]
pub struct HMACKey(pub [u8;32]);

impl <'a> HMACKey {
    pub fn new(hmac_salt: &Salt, password: &'a [u8]) -> HMACKey {
        let Salt(salt) = *hmac_salt;
        let mut mac = Hmac::new(Sha1::new(), password);
        let mut result: Vec<u8> = repeat(0).take(32).collect();
        pbkdf2(&mut mac, &salt[..], 10_000, &mut result[..]);
        HMACKey(*array_ref!(result, 0, 32))
    }
}

#[derive (Debug)]
pub struct Header<'a>(&'a IV);

#[derive (Debug, PartialEq, Eq)]
pub struct IV(pub [u8;16]);

impl Display for IV {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            IV(ref v) => write!(f, "{:?}", v),
        }
    }
}

#[derive (Debug)]
pub struct Password<'a>(&'a [u8]);
#[derive (Debug)]
pub struct PlainText<'a>(&'a [u8]);

#[derive (Debug)]
pub struct Message(Vec<u8>);

fn random_data_of_len(size: usize) -> StdResult<Vec<u8>, std::io::Error> {
    Ok(try!(OsRng::new().map(|mut gen| gen.gen_iter().take(size).collect::<Vec<u8>>())))
}

impl IV {
    pub fn new() -> Result<IV> {
        match random_data_of_len(16) {
            Err(e) => Err(errors::Error::new(ErrorKind::IVGenerationFailed(e), "IV Generation failed.".to_owned())),
                Ok(v) => Ok(IV(*array_ref!(v, 0,16)))
        }
    }
}

pub fn encrypt(password: &str, plain_text: &PlainText) -> Result<Message> {
    if password.len() <= 0 {
        return Err(errors::Error::new(errors::ErrorKind::WrongInputSize(password.len()),
                                      "Password length cannot be <= 0.".to_owned()))
    }
    let iv = try!(IV::new());
    let header = Header(&iv);
    //let cipher_text = CipherText::new(plain_text, &iv, encryption_key);
    //let hmac = HMAC::new(&header, &cipher_text, hmac_key);
    //Ok(Message::new(&header, &cipher_text, &hmac))
    Ok(Message(Vec::from("umeboshi".as_bytes())))
}

pub fn encrypt_with_key(encryption_key: &EncryptionKey, hmac_key: &HMACKey, plain_text: &PlainText) -> Result<Message> {
    let iv = try!(IV::new());
    let header = Header(&iv);
    //let cipher_text = CipherText::new(plain_text, &iv, encryption_key);
    //let hmac = HMAC::new(&header, &cipher_text, hmac_key);
    //Ok(Message::new(&header, &cipher_text, &hmac))
    Ok(Message(Vec::from("umeboshi".as_bytes())))
}

pub fn decrypt(password: &Password, message: &Message) -> Result<Vec<u8>> {
    Ok(Vec::from("umeboshi".as_bytes()))
}
