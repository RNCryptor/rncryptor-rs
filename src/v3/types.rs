
extern crate rand;
extern crate crypto;

use self::crypto::pbkdf2::pbkdf2;
use std::iter::repeat;
use self::crypto::hmac::Hmac;
use self::crypto::aes;
use self::crypto::mac::Mac;
use self::crypto::buffer::{WriteBuffer, ReadBuffer, RefReadBuffer, RefWriteBuffer, BufferResult};
use self::crypto::sha1::Sha1;
use self::crypto::sha2::Sha256;
use self::crypto::blockmodes;
use self::rand::{Rng, OsRng};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result::Result as StdResult;
use std;

use v3::errors::{Result, Error, ErrorKind};

#[derive (Debug)]
pub struct EncryptionKey(Vec<u8>);

impl <'a> EncryptionKey {
    pub fn new(encryption_salt: &Salt, password: &'a [u8]) -> EncryptionKey {
        EncryptionKey(new_key_with_salt(encryption_salt, password))
    }
}

#[derive (Debug)]
pub struct Salt(pub Vec<u8>);

impl Salt {
    pub fn new() -> Result<Salt> {
        match random_data_of_len(8) {
            Err(e) => Err(Error::new(ErrorKind::SaltGenerationFailed(e), "Salt Generation failed.".to_owned())),
            Ok(v) => Ok(Salt(v))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        let Salt(ref s) = *self;
        s
    }
}

#[derive (Debug, PartialEq, Eq)]
pub struct HMACKey(pub Vec<u8>);

fn new_key_with_salt<'a>(salt: &Salt, password: &'a [u8]) -> Vec<u8> {
        let Salt(ref salt) = *salt;
        let mut mac = Hmac::new(Sha1::new(), password);
        let mut result: Vec<u8> = repeat(0).take(32).collect();
        pbkdf2(&mut mac, &salt[..], 10_000, &mut result[..]);
        result
}

impl <'a> HMACKey {
    pub fn new(hmac_salt: &Salt, password: &'a [u8]) -> HMACKey {
        HMACKey(new_key_with_salt(hmac_salt, password))
    }
}

#[derive (Debug)]
pub struct Header(pub Vec<u8>);

#[derive (Debug, PartialEq, Eq)]
pub struct IV(pub Vec<u8>);

impl Display for IV {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            IV(ref v) => write!(f, "{:?}", v),
        }
    }
}

pub type Password  = [u8];
pub type PlainText = [u8];
pub type Message = Vec<u8>;

fn random_data_of_len(size: usize) -> StdResult<Vec<u8>, std::io::Error> {
    Ok(try!(OsRng::new().map(|mut gen| gen.gen_iter().take(size).collect::<Vec<u8>>())))
}

impl IV {
    pub fn new() -> Result<IV> {
        match random_data_of_len(16) {
            Err(e) => Err(Error::new(ErrorKind::IVGenerationFailed(e), "IV Generation failed.".to_owned())),
                Ok(v) => Ok(IV(v))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        let IV(ref s) = *self;
        s
    }
}

pub struct CipherText(pub Vec<u8>);

impl CipherText {
    pub fn new(plain_text: &PlainText, iv: &IV, encryption_key: &EncryptionKey) -> Result<CipherText> {
        let IV(ref iv_ref) = *iv;
        let EncryptionKey(ref key) = *encryption_key;
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv_ref,
            blockmodes::PkcsPadding);

        // Usage taken from: https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs
        let mut final_result = Vec::<u8>::new();
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);
        let mut read_buffer  = RefReadBuffer::new(plain_text);

        loop {
            let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)
                              .map_err(ErrorKind::EncryptionFailed));

            // "write_buffer.take_read_buffer().take_remaining()" means:
            // from the writable buffer, create a new readable buffer which
            // contains all data that has been written, and then access all
            // of that data as a slice.
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        Ok(CipherText(final_result))

    }
}

pub struct HMAC(pub Vec<u8>);

impl HMAC {
    pub fn new(header: &Header, cipher_text: &CipherText, hmac_key: &HMACKey) -> HMAC {
        let HMACKey(ref key) = *hmac_key;
        let Header(ref h) = *header;
        let CipherText(ref txt) = *cipher_text;
        let mut hmac = Hmac::new(Sha256::new(), key);

        let mut input = Vec::new();
        input.extend(h);
        input.extend(txt.as_slice());

        hmac.input(&input);
        // TODO: Avoid Vec use.
        HMAC(Vec::from(hmac.result().code()))
    }
}

pub type EncryptionSalt = Salt;
pub type HMACSalt = Salt;
