extern crate quickcheck;
extern crate rncryptor;

use quickcheck::quickcheck;
use rncryptor::v3;

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
    quickcheck(encrypt_decrypt_yields_the_same as fn(Vec<u8>) -> bool);
}
