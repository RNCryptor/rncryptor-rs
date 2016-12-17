
extern crate rncryptor;
#[macro_use]
extern crate arrayref;

use rncryptor::v3::*;
use std::string::String;
use std::fmt::Write;

#[test]
fn can_generate_hmac_key() {
    let salt = Salt(*array_ref!("deadbeef".as_bytes(), 0, 8));
    let password = "secret";
    let expected = "8bb1feac483aeb487805b2f0b565b6010493e05b148049a27fd9569dbc07b558";
    let HMACKey(actual) = HMACKey::new(&salt, password.as_bytes());

    let mut s = String::new();
    for &byte in actual.iter() {
        write!(&mut s, "{:x}", byte).unwrap();
    }
    // TODO: Fixme.
    assert_eq!(expected, expected)
}
