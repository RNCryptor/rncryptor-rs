
extern crate crypto;

use std::result::Result as StdResult;
use std;

pub type Result<T> = StdResult<T, Error>;

/// All the things which can go wrong :)
#[derive(Debug)]
pub enum ErrorKind {
    /// The generation of the HMAC failed.
    HMACGenerationFailed,
    /// The final check between the embedded HMAC and the computed one failed.
    HMACValidationFailed,
    /// The HMAC wasn't found inside the encrypted packed during decryption.
    HMACNotFound,
    /// The input size was wrong.
    WrongInputSize(usize),
    /// Not enough input for decryption.
    NotEnoughInput(usize),
    /// The IV generation failed.
    IVGenerationFailed(std::io::Error),
    /// The Salt generation failed.
    SaltGenerationFailed(std::io::Error),
    /// The encryption failed, due to an error raised from the downstream crypto layer.
    EncryptionFailed(crypto::symmetriccipher::SymmetricCipherError),
    /// The decryption failed, due to an error raised from the downstream crypto layer.
    DecryptionFailed(crypto::symmetriccipher::SymmetricCipherError),
}

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
}

impl From<ErrorKind> for Error {
    fn from(e: ErrorKind) -> Error {
        Error {
            message: String::from("RNCryptor failed"),
            kind: e,
        }
    }
}

impl Error {
    pub fn new(k: ErrorKind, m: String) -> Error {
        Error {
            message: m,
            kind: k,
        }
    }
}
