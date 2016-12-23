
///! `Error` and `ErrorKind` types.
pub mod errors;
///! The types.
pub mod types;
///! "Low-level" encryption abstractions.
pub mod encryptor;
///! "Low-level" decryption abstractions.
pub mod decryptor;

use v3::types::{Salt, IV, PlainText, Message};
use v3::encryptor::{Encryptor};
use v3::decryptor::{Decryptor};
use v3::errors::{Result};

///! Encrypts a `PlainText` with the given password, producing either an encrypted
///! `Message` or an `Error` otherwise.
///!
///! **Note: This is NOT a streaming function.**
pub fn encrypt(password: &str, plain_text: &PlainText) -> Result<Message> {
    let esalt = try!(Salt::new());
    let hsalt = try!(Salt::new());
    let iv = try!(IV::new());
    let encryptor = try!(Encryptor::from_password(password, esalt, hsalt, iv));
    encryptor.encrypt(plain_text)
}

// TODO: Make API signature simmetric.
///! Decrypts a `Message` with the given password, producing either a decrypted
///! `Vec<u8>` or an `Error` otherwise.
///!
///! **Note: This is NOT a streaming function.**
pub fn decrypt(password: &str, message: &Message) -> Result<Vec<u8>> {
    let decryptor = try!(Decryptor::from(password, message));
    decryptor.decrypt(message)
}
