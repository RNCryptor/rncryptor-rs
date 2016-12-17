
extern crate crypto;

use self::errors::Result;

mod errors;

/// ! `rncryptor-rs` is a pure Rust implementation of
/// ! the [RNCryptor](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
/// ! V3 format by Rob Napier.

pub struct EncryptionKey<'a>(&'a [u8;32]);
pub struct HMACKey<'a>(&'a [u8;32]);
pub struct Password<'a>(&'a [u8]);
pub struct PlainText<'a>(&'a [u8]);
pub struct Message(Vec<u8>);

pub fn encrypt(encryption_key: &EncryptionKey, hmac: &HMACKey, plain_text: &PlainText) -> Result<Message> {
    Ok(Message(Vec::from("umeboshi".as_bytes())))
}

pub fn decrypt(password: &Password, message: &Message) -> Result<Vec<u8>> {
    Ok(Vec::from("umeboshi".as_bytes()))
}
