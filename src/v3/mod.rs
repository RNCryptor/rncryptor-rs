
extern crate crypto;
extern crate rand;

use self::crypto::pbkdf2::pbkdf2;
use std::iter::repeat;
use self::crypto::hmac::Hmac;
use self::crypto::sha1::Sha1;
use self::errors::{Result, ErrorKind};
use self::rand::{Rng, OsRng};
use std::fmt::{Display, Formatter, Result as FmtResult};

mod errors;

/// ! `rncryptor-rs` is a pure Rust implementation of
/// ! the [RNCryptor](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
/// ! V3 format by Rob Napier.

#[derive (Debug)]
pub struct EncryptionKey<'a>(&'a [u8;32]);

#[derive (Debug)]
pub struct HMACSalt(pub [u8;8]);

#[derive (Debug, PartialEq, Eq)]
pub struct HMACKey(pub [u8;32]);

impl <'a> HMACKey {
    pub fn new(hmac_salt: &HMACSalt, password: &'a [u8]) -> HMACKey {
        let HMACSalt(salt) = *hmac_salt;
        let mut mac = Hmac::new(Sha1::new(), password);
        let mut result: Vec<u8> = repeat(0).take(32).collect();
        pbkdf2(&mut mac, &salt[..], 10_000, &mut result[..]);
        HMACKey(*array_ref!(result, 0, 32))
    }
}

#[derive (Debug)]
pub struct Header<'a>(&'a IV);

#[derive (Debug, PartialEq, Eq)]
pub struct IV(pub Vec<u8>);

impl Display for IV {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            IV(ref v) => write!(f, "{:?}", v.as_slice()),
        }
    }
}

#[derive (Debug)]
pub struct Password<'a>(&'a [u8]);
#[derive (Debug)]
pub struct PlainText<'a>(&'a [u8]);

#[derive (Debug)]
pub struct Message(Vec<u8>);

impl IV {
    pub fn new(size: usize) -> Result<IV> {
        Ok(try!(OsRng::new().map_err(ErrorKind::IVGenerationFailed)
                .map(|mut gen| IV(gen.gen_iter().take(size).collect::<Vec<u8>>()))))
    }
}

pub fn encrypt(encryption_key: &EncryptionKey, hmac_key: &HMACKey, plain_text: &PlainText) -> Result<Message> {
    let iv = try!(IV::new(16));
    let header = Header(&iv);
    //let cipher_text = CipherText::new(plain_text, &iv, encryption_key);
    //let hmac = HMAC::new(&header, &cipher_text, hmac_key);
    //Ok(Message::new(&header, &cipher_text, &hmac))
    Ok(Message(Vec::from("umeboshi".as_bytes())))
}

pub fn decrypt(password: &Password, message: &Message) -> Result<Vec<u8>> {
    Ok(Vec::from("umeboshi".as_bytes()))
}
