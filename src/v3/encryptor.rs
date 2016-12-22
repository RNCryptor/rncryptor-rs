
extern crate crypto;

use v3::types::*;
use v3::errors::{Result, Error, ErrorKind};
use self::crypto::buffer::{WriteBuffer, ReadBuffer, RefReadBuffer, RefWriteBuffer, BufferResult};
use self::crypto::aes;
use self::crypto::blockmodes;

#[derive(Clone)]
pub struct Encryptor {
    encryption_key: EncryptionKey,
    hmac_key: HMACKey,
    header: Header,
    iv: IV,
}

impl Encryptor {
    pub fn from_password(password: &str,
                         es: EncryptionSalt,
                         hs: HMACSalt,
                         iv: IV)
                         -> Result<Encryptor> {

        if password.len() <= 0 {
            return Err(Error::new(ErrorKind::WrongInputSize(password.len()),
                                  "Password length cannot be <= 0.".to_owned()));
        }

        let mut header: Vec<u8> = Vec::new();
        header.push(3);
        header.push(1);
        header.extend(es.as_slice().iter());
        header.extend(hs.as_slice().iter());
        header.extend(iv.as_slice().iter());

        Ok(Encryptor {
            encryption_key: EncryptionKey::new(&es, password.as_bytes()),
            hmac_key: HMACKey::new(&hs, password.as_bytes()),
            header: Header(header),
            iv: iv,
        })
    }

    pub fn from_keys(ek: EncryptionKey, hk: HMACKey, iv: IV) -> Result<Encryptor> {

        let mut header: Vec<u8> = Vec::new();
        header.push(3);
        header.push(0);
        header.extend(iv.as_slice().iter());

        Ok(Encryptor {
            encryption_key: ek,
            hmac_key: hk,
            header: Header(header),
            iv: iv,
        })
    }

    pub fn cipher_text<X: blockmodes::PaddingProcessor + Send + 'static>(&self, padding: X, plain_text: &PlainText) -> Result<CipherText> {
        let iv = self.iv.to_vec();
        let key = self.encryption_key.to_vec();
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            padding);

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

    pub fn encrypt(&self, plain_text: &PlainText) -> Result<Message> {

        // If the input is empty, pad it with Pkcs7 in full.
        let cipher_text = match plain_text.is_empty() {
            true  => try!(self.cipher_text(blockmodes::NoPadding, vec![16;16].as_slice())),
            false => try!(self.cipher_text(blockmodes::PkcsPadding, &plain_text)),
        };

        let CipherText(ref text) = cipher_text;

        let HMAC(hmac) = try!(HMAC::new(&self.header, &cipher_text, &self.hmac_key));

        let mut message = Vec::new();

        let Header(ref header) = self.header;
        message.extend(header.as_slice());
        message.extend(text);
        message.extend(hmac.as_slice());

        Ok(message)
    }
}
