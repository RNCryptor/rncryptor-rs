
extern crate rncryptor;

use rncryptor::v3::*;

#[test]
fn can_generate_iv() {
    assert!(IV::new(16).is_ok())
}

#[test]
fn iv_is_16_elem_long() {
    match IV::new(16) {
        Err(e) => panic!(e),
        Ok(IV(iv)) => assert_eq!(iv.len(), 16),
    }
}
