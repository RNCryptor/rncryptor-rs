
/*!
`rncryptor-rs` is a pure Rust implementation of the [RNCryptor](https://github.com/RNCryptor) file
format by [Rob Napier](https://twitter.com/cocoaphony). It currently supports
[Version 3](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md) and aims
to be written with a clean, easy to use API which matches the abstract pseudocode
found in the spec.

## Simple Usage
It's likely you want to dive straight into how to use the library for encryption and decryption
of data, which can be done easily with the two functions `encrypt` and `decrypt`. **Note that
these are not streaming functions and will try to load the entire content to encrypt/decrypt
into memory, which might not be what you want. Streaming functions are in the works (PRs welcome!)**

To encrypt something, simply call `encrypt`:

```ignore
extern crate rncryptor;
use rncryptor::v3;

let result = v3::encrypt("password", "secret".to_owned());
```

Decrypting is easy as well:

```ignore
extern crate rncryptor;
use rncryptor::v3;

let encrypted = ... // A `Message` as encrypted by "encrypt".
let plain_text = v3::decrypt("password", &encrypted));
```

## Advanced Usage
Sometimes you might want to have more control over the encryption/decryption process, and that's where the
`Encryptor` and `Decryptor` data structures come into play, as they allow to fine-tune things like the `Salt`,
the `IV` and encrypt either by using the "password-based" API or the "key-based" API (check the Specs for more
details).

```ignore
extern crate rncryptor;

use rncryptor::v3::encryptor::Encryptor;
use rustc_serialize::hex::FromHex;
use rncryptor::v3::types::*;

let encryption_salt = Salt("0203040506070001".from_hex().unwrap());
let hmac_salt = Salt("0304050607080102".from_hex().unwrap());
let iv = IV::from("0405060708090a0b0c0d0e0f00010203".from_hex().unwrap());
let plain_text = (0..).take(1_000_000).collect::<Vec<_>>();
let e = Encryptor::from_password("thepassword", encryption_salt, hmac_salt, iv);
match e {
    Err(_)  => panic!("bench_encryption init failed."),
    Ok(enc) => enc.encrypt(&plain_text),
}
```

*/



pub mod v3;

