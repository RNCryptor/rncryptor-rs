
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

pub enum ErrorKind {
    HMACValidationFailed,
    WrongInputSize(u8),
}

pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
}

impl Error {
    pub fn new(k: ErrorKind, m: String) -> Error {
        Error {
            message: m,
            kind: k,
        }
    }
}
