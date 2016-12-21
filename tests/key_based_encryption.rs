extern crate rustc_serialize;
extern crate rncryptor;

use rustc_serialize::hex::FromHex;
use rncryptor::v3::types::*;
use rncryptor::v3::encryptor::Encryptor;

struct TestVector {
    encryption_key: &'static str,
    hmac_key: &'static str,
    iv: &'static str,
    plain_text: &'static str,
    cipher_text: &'static str,
}

fn test_vector(vector: TestVector) {
    let encryption_key = EncryptionKey::from(vector.encryption_key.from_hex().unwrap());
    let hmac_key = HMACKey::from(vector.hmac_key.from_hex().unwrap());
    let iv = IV::from(vector.iv.from_hex().unwrap());
    let plain_text = vector.plain_text.from_hex().unwrap();
    let ciphertext = vector.cipher_text.from_hex().unwrap();
    let result = Encryptor::from_keys(encryption_key, hmac_key, iv)
        .and_then(|e| e.encrypt(&plain_text));
    match result {
        Err(e) => panic!(e),
        Ok(encrypted) => assert_eq!(*encrypted.as_slice(), *ciphertext.as_slice()),
    }
}

#[test]
fn all_fields_empty_or_zero() {
    test_vector(TestVector {
        encryption_key: "0000000000000000000000000000000000000000000000000000000000000000",
        hmac_key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        plain_text: "",
        cipher_text: "03000000 00000000 00000000 00000000 00001f78 8fe6d86c 31754969 7fbf0c07 \
                      fa436384 ac0ef35b 860b2ddb 2aba2fff 816b1fb3 a9c180f7 b43650ae c0d2b5f8 8e33",
    })
}

#[test]
fn one_byte() {
    test_vector(TestVector {
        encryption_key: "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
        hmac_key: "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00",
        iv: "02030405060708090a0b0c0d0e0f0001",
        plain_text: "01",
        cipher_text: "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 \
                      e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5",
    })
}

#[test]
fn exactly_one_block() {
    test_vector(TestVector {
        encryption_key: "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00",
        hmac_key: "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
        iv: "030405060708090a0b0c0d0e0f000102",
        plain_text: "000102030405060708090a0b0c0d0e0f",
        cipher_text: "03000304 05060708 090a0b0c 0d0e0f00 0102d2b1 77d61878 1829f564 53f739a2 \
                      d4f729f9 2b1a9c6c 50837864 74e16a22 c60f92b0 73454f79 76cdda04 3e09b117 \
                      66de05ff e05bc1dc a9522ea6 6e64ad25 bbbc",
    })
}

#[test]
fn more_than_one_block() {
    test_vector(TestVector {
        encryption_key: "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
        hmac_key: "030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102",
        iv: "0405060708090a0b0c0d0e0f00010203",
        plain_text: "000102030405060708090a0b0c0d0e0f 000102030405060708",
        cipher_text: "03000405 06070809 0a0b0c0d 0e0f0001 02034c9b 98b425f1 d732644c b311278d \
                      858e3d18 2a0789b8 6af7f741 34b6a27e 9d938617 741c0fb8 aaf094b3 b5b26f50 \
                      5da7bf19 13f6c17e 70273977 ae51323b 6f09",
    })
}
