
extern crate rncryptor;

use rncryptor::v3::types::*;

#[test]
fn can_generate_iv() {
    assert!(IV::new().is_ok())
}

#[test]
fn iv_is_16_elem_long() {
    match IV::new() {
        Err(e) => panic!(e),
        Ok(IV(iv)) => assert_eq!(iv.len(), 16),
    }
}
