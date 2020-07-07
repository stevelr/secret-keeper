#[cfg(test)]
//
//
use bytes::BytesMut;
use lazy_static::lazy_static;
use random_fast_rng::{FastRng, Random};
use secret_keeper::{
    error::{Error, Result},
    keepers::SecretKeeper,
    util::{getenv, getenv_default, uninitialized_bytes},
};
use std::env;
use std::sync::Mutex;

use super::vault_client::*;
use super::{HashivaultKeeper, HashivaultOptions};

// name of environment variable holding key type to be used for tests.
// If not defined, default of "aes256-gcm96" is used
const KEYTYPE_ENV: &str = "VAULT_KEY_TYPE";
const DEFAULT_KEYTYPE: &str = "aes256-gcm96";
const DEFAULT_VAULT_ADDR: &str = "http://127.0.0.1:8200/";

lazy_static! {
    // Because some of tests modify the environment variable (VAULT_TOKEN).
    // we use this static TOKEN to store the original value before any test changed it.
    //
    // The hashivault library does use the normal env::var, so any test case that
    // is not specifically testing the environment var handling must do one of the following:
    // either hold the mutex during the duration of the test (which ensures the env var
    // is stable and equal to the original value), or, preferably, use test_getenv() to get the
    // correct unmodified value and set the 'token' query param in the url. The library
    // function only uses the environment value if it's not set in the url.
    // The second option is preferred so that tests can run with greater parallelism.
    static ref TOKEN: Mutex<Option<String>> =Mutex::new(None);
}

/// thread-safe (and multithread test-safe) function to fetch VAULT_TOKEN from environment
/// Returns Err if not defined (which should cause test to fail)
fn test_getenv() -> Result<String, Error> {
    let mut token = TOKEN.lock().unwrap();

    match token.as_ref() {
        Some(val) => Ok(val.to_string()),
        None => {
            // The first time this is invoked, initialize TOKEN from environment
            let val = getenv(VAULT_TOKEN)?; // or return Err if not defined
            *token = Some(val.clone());
            Ok(val)
        }
    }
}

#[tokio::test]
/// wrap and unwrap using the keeper api
async fn hashivault_wrap_unwrap() -> Result<(), Error> {
    let token = test_getenv()?;
    assert!(token.len() > 0);
    println!("wrap_unwrap, token={}", token);
    let vault_keyname = format!("test_key_{}", hex::encode(random_bytes(4)));
    let uri = format!("hashivault://{}?token={}", vault_keyname, token);

    let spec = ClientSpec::from_uri(&uri)?;
    // create key on vault
    println!("about to create key, uri={}", &uri);
    let key_type = getenv_default(KEYTYPE_ENV, DEFAULT_KEYTYPE);
    let _ = create_key(&spec, &key_type).await?;
    println!("wrap_unwrap: created key (type {}): {:#?}", key_type, spec);

    let keeper = HashivaultKeeper::new(HashivaultOptions::defaults()).await?;
    println!("wrap_unwrap: keeper created");

    let key = random_bytes(32);
    let nonce = random_bytes(16);
    let wrapped = keeper.wrap(&uri, &nonce, &key).await?;
    println!("wrap_unwrap: wrapped");
    let unwrapped = keeper.unwrap(&nonce, &wrapped).await?;
    println!("wrap_unwrap: unwrapped");
    assert!(arrays_eq(&key, &unwrapped.as_ref()));

    // cleanup
    let _ = delete_key(&spec).await?;

    println!("wrap_unwrap: done!!");
    Ok(())
}

#[tokio::test]
/// encrypt and decrypt using vault_client api
async fn hashivault_encrypt_decrypt() -> Result<(), Error> {
    let token = test_getenv()?;
    let key_type = getenv_default(KEYTYPE_ENV, DEFAULT_KEYTYPE);
    let vault_keyname = format!("test_key_{}", hex::encode(random_bytes(5)));

    let spec = ClientSpec::from_uri(&format!("hashivault://{}?token={}", vault_keyname, token))?;
    let _ = create_key(&spec, &key_type).await?;

    let plaintext: &[u8] = "Your base are encrypted".as_bytes();
    let ciphertext = encrypt(&spec, plaintext).await?;
    let binresult = decrypt(&spec, ciphertext).await?;

    assert!(arrays_eq(plaintext, &binresult));

    // cleanup
    let _ = delete_key(&spec).await?;
    Ok(())
}

fn remove_trailing_slash(s: &str) -> &str {
    if s.ends_with("/") {
        &s[..(s.len() - 1)]
    } else {
        s
    }
}

#[test]
/// test url parsing: extract host, port, key, inferred scheme
fn hashivault_uri_parse() -> Result<(), Error> {
    let _guard = TOKEN.lock();
    let spec = ClientSpec::from_uri("hashivault://mykey?token=123")?;
    let vault_addr = getenv_default("VAULT_ADDR", DEFAULT_VAULT_ADDR);
    let addr = remove_trailing_slash(&vault_addr);

    assert_eq!(spec.base_url, addr);
    assert_eq!(spec.key_name, "mykey");
    assert_eq!(spec.token, "123");

    let spec = ClientSpec::from_uri("hashivault://localhost/mykey?token=123")?;
    assert_eq!(spec.base_url, "http://localhost:8200");
    assert_eq!(spec.key_name, "mykey");
    assert_eq!(spec.token, "123");

    let spec = ClientSpec::from_uri("hashivault://someserver/mykey?token=123")?;
    assert_eq!(spec.base_url, "https://someserver:8200");
    assert_eq!(spec.key_name, "mykey");
    assert_eq!(spec.token, "123");

    let spec = ClientSpec::from_uri("hashivault://localhost:7777/mykey?token=123")?;
    assert_eq!(spec.base_url, "http://localhost:7777");
    assert_eq!(spec.key_name, "mykey");
    assert_eq!(spec.token, "123");
    Ok(())
}

#[test]
/// test url parsing: host, port
fn hashivault_uri_hostport() -> Result<(), Error> {
    let spec = ClientSpec::from_uri("hashivault://mykey?token=123")?;
    let vault_addr = getenv_default("VAULT_ADDR", DEFAULT_VAULT_ADDR);
    let addr = remove_trailing_slash(&vault_addr);
    assert_eq!(
        spec.base_url, addr,
        "default host+port: got base url {}, expected {}",
        spec.base_url, addr
    );

    let spec = ClientSpec::from_uri("hashivault://server:1234/mykey?token=123")?;
    assert_eq!(
        spec.base_url, "https://server:1234",
        "override host+port: got base url {}, expected {}",
        spec.base_url, "https://server:1234"
    );

    let spec = ClientSpec::from_uri("hashivault://localhost:1234/mykey?token=123")?;
    assert_eq!(
        spec.base_url, "http://localhost:1234",
        "override port: got base url {}, expected {}",
        spec.base_url, "http://localhost:1234"
    );
    Ok(())
}

#[test]
/// test url parsing: inferred scheme
fn hashivault_uri_infer_scheme() -> Result<(), Error> {
    let spec = ClientSpec::from_uri("hashivault://localhost:8080/mykey?token=123")?;
    assert_eq!(
        spec.base_url, "http://localhost:8080",
        "infer http for localhost: got base url {}, expected {}",
        spec.base_url, "http://localhost:8080"
    );

    let spec = ClientSpec::from_uri("hashivault://other.example.net:8080/mykey?token=123")?;
    assert_eq!(
        spec.base_url, "https://other.example.net:8080",
        "infer https for non-localhost: got base url {}, expected {}",
        spec.base_url, "https://other.example.net:8080"
    );
    Ok(())
}

#[test]
/// test url parsing: override scheme
fn hashivault_uri_override_scheme() -> Result<(), Error> {
    let _guard = TOKEN.lock();

    let spec = ClientSpec::from_uri("hashivault:http://localhost:8080/mykey?token=123")?;
    assert_eq!(
        &spec.base_url, "http://localhost:8080",
        "got:{} expected http://localhost:8080",
        spec.base_url
    );

    let spec = ClientSpec::from_uri("hashivault:https://localhost:8080/mykey?token=123")?;
    assert_eq!(
        &spec.base_url, "https://localhost:8080",
        "got:{} expected https://localhost:8080",
        spec.base_url
    );

    let spec = ClientSpec::from_uri("hashivault:http://other.example.com:8080/mykey?token=123")?;
    assert_eq!(
        &spec.base_url, "http://other.example.com:8080",
        "got:{} expected http://other.example.com:8080",
        spec.base_url
    );

    let spec = ClientSpec::from_uri("hashivault:https://other.example.com:8080/mykey?token=123")?;
    assert_eq!(
        &spec.base_url, "https://other.example.com:8080",
        "got:{} expected https://other.example.com:8080",
        spec.base_url
    );
    Ok(())
}

#[test]
/// test url token and environment token
fn hashivault_uri_token() -> Result<(), Error> {
    let orig_value = test_getenv()?;
    let _guard = TOKEN.lock();

    // clear from environment, should generate error
    env::set_var(VAULT_TOKEN, "");
    let r = ClientSpec::from_uri("hashivault://mykey");
    assert!(
        r.is_err(),
        "expect err for missing token, found {:#?}",
        env::var(VAULT_TOKEN)
    );

    // empty token is invalid
    let r = ClientSpec::from_uri("hashivault://mykey?token");
    assert!(r.is_err(), "expect err for empty token: {:#?}", r);

    // set known token from environment, verify it is used as default
    env::set_var(VAULT_TOKEN, "abc123");
    let r = ClientSpec::from_uri("hashivault://mykey");
    assert!(r.is_ok(), "env token");
    let spec = r.unwrap();
    assert_eq!(
        spec.token, "abc123",
        "token {} from environment",
        spec.token
    );

    // different token from uri should override env
    let spec = ClientSpec::from_uri("hashivault://mykey?token=thisone")?;
    assert_eq!(spec.token, "thisone", "token {} from url", spec.token);

    // restore the value from start of test
    env::set_var(VAULT_TOKEN, orig_value);
    Ok(())
}

#[test]
/// test error handling for missing key
fn hashivault_uri_missing_key() -> Result<(), Error> {
    let r = ClientSpec::from_uri("hashivault://");
    assert!(r.is_err(), "missing key");
    Ok(())
}

#[test]
/// test error handling for wrong scheme
fn hashivault_uri_wrong_scheme() -> Result<(), Error> {
    let r = ClientSpec::from_uri("foo://mykey");
    assert!(r.is_err(), "invalid scheme");
    Ok(())
}

/// compare two arrays for equality
/// Returns true if arrays have the same length and corresponding elements are "equal"
fn arrays_eq<T: PartialEq>(a1: &[T], a2: &[T]) -> bool {
    a1.len() == a2.len() && a1.iter().zip(a2.iter()).all(|(a, b)| a == b)
}

/// Create a BytesMut buffer and fill with random data. NOT cryptographically secure.
/// Used only for testing.
fn random_bytes(len: usize) -> BytesMut {
    let mut buf = uninitialized_bytes(len);
    FastRng::new().fill_bytes(buf.as_mut());
    buf
}
