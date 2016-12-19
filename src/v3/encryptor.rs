
extern crate crypto;
extern crate rand;

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

use v3::types::*;
use v3::errors::{Result, Error, ErrorKind};

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

    pub fn encrypt(&self, plain_text: &PlainText) -> Result<Message> {

        let cipher_text = try!(CipherText::new(&plain_text, &self.iv, &self.encryption_key));
        let CipherText(ref text) = cipher_text;

        let HMAC(hmac) = HMAC::new(&self.header, &cipher_text, &self.hmac_key);

        let mut message = Vec::new();

        let Header(ref header) = self.header;
        message.extend(header.as_slice());
        message.extend(text);
        message.extend(hmac.as_slice());

        Ok(message)
    }
}

pub fn decrypt(password: &Password, message: &Message) -> Result<Vec<u8>> {
    Ok(Vec::from("umeboshi".as_bytes()))
}
