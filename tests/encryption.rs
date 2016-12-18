extern crate rustc_serialize;
extern crate rncryptor;

use rustc_serialize::hex::FromHex;
use rncryptor::v3::{Encryptor, IV, Salt};

#[test]
fn test_password_encryption() {
    let password = "thepassword";
    let encryption_salt = Salt("0001020304050607".from_hex().unwrap());
    let hmac_salt = Salt("0102030405060708".from_hex().unwrap());
    let iv = IV("02030405060708090a0b0c0d0e0f0001".from_hex().unwrap());
    let plain_text = "01".from_hex().unwrap();
    let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f \
                      0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca \
                      545b7de3 de5b010a cbad0a9a 13857df6 96a8"
        .from_hex()
        .unwrap();
    let result = Encryptor::from(password, encryption_salt, hmac_salt, iv).encrypt(&plain_text);
    match result {
        Err(e) => panic!(e),
        Ok(encrypted) => assert_eq!(*encrypted.as_slice(), *ciphertext.as_slice()),
    }
}
