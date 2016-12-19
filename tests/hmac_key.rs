
extern crate rncryptor;
extern crate rustc_serialize;

use rncryptor::v3::types::*;
use rustc_serialize::hex::FromHex;
use std::string::String;
use std::fmt::Write;

#[test]
fn can_generate_hmac_key() {
    let salt = Salt(Vec::from("deadbeef"));
    let password = "secret";
    let expected = "8bb1feac 483aeb48 7805b2f0 b565b601 \
                    0493e05b 148049a2 7fd9569d bc07b558"
        .from_hex()
        .unwrap();
    let HMACKey(actual) = HMACKey::new(&salt, password.as_bytes());

    assert_eq!(actual, expected)
}
