
pub mod errors;
pub mod types;
pub mod encryptor;
pub mod decryptor;

use v3::types::{Salt, IV, PlainText, Message};
use v3::encryptor::{Encryptor};
use v3::decryptor::{Decryptor};
use v3::errors::{Result};

//`rncryptor-rs` is a pure Rust implementation of
//the [RNCryptor](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
//V3 format by Rob Napier.

pub fn encrypt(password: &str, plain_text: &PlainText) -> Result<Message> {
    let esalt = try!(Salt::new());
    let hsalt = try!(Salt::new());
    let iv = try!(IV::new());
    let encryptor = try!(Encryptor::from_password(password, esalt, hsalt, iv));
    encryptor.encrypt(plain_text)
}

// TODO: Make API signature simmetric.
pub fn decrypt(password: &str, message: &Message) -> Result<Vec<u8>> {
    let decryptor = try!(Decryptor::from(password, message));
    decryptor.decrypt(message)
}
