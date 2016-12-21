extern crate quickcheck;
extern crate rncryptor;

use quickcheck::QuickCheck;
use rncryptor::v3;

#[test]
fn test_simple_roundtrip() {
    let result = v3::encrypt("password", "secret".as_bytes())
        .and_then(|encrypted| v3::decrypt("password", &encrypted));
    match result {
        Err(e) => panic!(format!("{:?}", e.kind)),
        Ok(v) => assert_eq!(v, "secret".as_bytes().to_vec()),
    }
}

#[test]
fn test_roundtrip() {
    fn encrypt_decrypt_yields_the_same(message: Vec<u8>) -> bool {
        let result = v3::encrypt("secret", message.as_slice())
            .and_then(|encrypted| v3::decrypt("secret", &encrypted));
        match result {
            Err(_) => false,
            Ok(v) => v == message,
        }
    }
    QuickCheck::new().tests(15).quickcheck(encrypt_decrypt_yields_the_same as fn(Vec<u8>) -> bool);
}
