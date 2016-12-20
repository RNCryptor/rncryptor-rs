
extern crate crypto;

use v3::types::*;
use v3::errors::{Result, Error, ErrorKind};
use self::crypto::aes;
use self::crypto::blockmodes;
use self::crypto::buffer::{WriteBuffer, ReadBuffer, RefReadBuffer, RefWriteBuffer, BufferResult};

pub struct Decryptor {
    version: u8,
    options: u8,
    encryption_salt: EncryptionSalt,
    hmac_salt: HMACSalt,
    encryption_key: EncryptionKey,
    hmac_key: HMACKey,
    iv: IV,
}

impl Decryptor {
    pub fn from(password: &str, message: &[u8]) -> Result<Decryptor> {
        let msg_len = message.len();
        if msg_len < 66 {
            return Err(Error::new(ErrorKind::NotEnoughInput(msg_len),
                                  "Decryption failed, not enough input.".to_owned()));
        }

        let version = message[0];
        let options = message[1];
        let encryption_salt = Salt(message[2..10].to_vec());
        let hmac_salt = Salt(message[10..18].to_vec());
        let iv = IV::from(message[18..34].to_vec());
        let encryption_key = EncryptionKey::new(&encryption_salt, password.as_bytes());
        let hmac_key = HMACKey::new(&hmac_salt, password.as_bytes());


        Ok(Decryptor {
            version: version,
            options: options,
            encryption_salt: encryption_salt,
            encryption_key: encryption_key,
            hmac_key: hmac_key,
            hmac_salt: hmac_salt,
            iv: iv,
        })

    }

    fn plain_text(&self, cipher_text: &[u8]) -> Result<Message> {
        let iv  = self.iv.to_vec();
        let key = self.encryption_key.to_vec();
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

        // Usage taken from: https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs
        let mut final_result = Vec::<u8>::new();
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);
        //TODO: Fixme, doesn't strip away the HMAC.
        let mut read_buffer  = RefReadBuffer::new(cipher_text);

        loop {
            let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)
                              .map_err(ErrorKind::DecryptionFailed));

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

        Ok(final_result)

    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Result<Message> {

        let mut header: Vec<u8> = Vec::new();
        header.push(3);
        header.push(1);
        header.extend(self.encryption_salt.as_slice().iter());
        header.extend(self.hmac_salt.as_slice().iter());
        header.extend(self.iv.as_slice().iter());

        let ciphertext_iter = cipher_text[34..].iter();

        // Try to find the HMAC at the end of the message.
        // TODO: Rewrite this bit with take and collect.
        let mut remaining = 32;
        let mut hmac0 = Vec::new();
        for v in ciphertext_iter.rev() {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            hmac0.push(*v)
        }
        if remaining != 0 {
            return Err(Error::new(ErrorKind::HMACNotFound,
                                  "No HMAC found at the end.".to_owned()));
        }

        let hmac = HMAC(hmac0);
        let message = try!(self.plain_text(cipher_text));

        Ok(message)
    }
}
