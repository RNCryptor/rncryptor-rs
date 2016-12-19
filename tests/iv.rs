
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
        Ok(iv) => assert_eq!(iv.as_slice().len(), 16),
    }
}
