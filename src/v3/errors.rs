
extern crate crypto;

use std::result::Result as StdResult;
use std;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug)]
pub enum ErrorKind {
    HMACValidationFailed,
    HMACNotFound,
    WrongInputSize(usize),
    NotEnoughInput(usize),
    IVGenerationFailed(std::io::Error),
    SaltGenerationFailed(std::io::Error),
    EncryptionFailed(crypto::symmetriccipher::SymmetricCipherError),
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
