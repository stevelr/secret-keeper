// src/util.rs

use crate::error::Error;

/// retrieve environment variable
pub fn getenv(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::OtherError(format!("Undefined environment var: {}", key)))
}

/// retrieve environment variable, with default value
pub fn getenv_default(key: &str, default_val: &str) -> String {
    match std::env::var(key) {
        Ok(v) => v,
        Err(_) => String::from(default_val),
    }
}

/// parse the list of key-value tuples to find the value associated with the given key.
/// This is useful for parsing the results of `serde_urlencoded::from_str`.
///
/// ```
///   use secret_keeper::util::form_get;
///   let fields = vec!{ ("one".to_string(),"apple".to_string()),
///                      ("two".to_string(),"banana".to_string()) };
///   assert_eq!(form_get(&fields, "one"), Some("apple"));
///   assert_eq!(form_get(&fields, "two"), Some("banana"));
///   assert_eq!(form_get(&fields, "three"), None);
/// ```
pub fn form_get<'v>(fields: &'v Vec<(String, String)>, key: &str) -> Option<&'v str> {
    fields.iter().find(|v| v.0 == key).map(|v| v.1.as_str())
}

#[cfg(test)]
mod test {

    use bytes::Bytes;
    use secret_keeper_test_util::random_bytes;

    #[test]
    fn gen_random() {
        let len = 20;

        // ensure generated array is correct length
        let b = random_bytes(len);
        assert_eq!(b.len(), len);

        // ensure it doesn't generate all zeroes
        let nonzero: Bytes = b.into_iter().filter(|x: &u8| *x != 0).collect();
        assert!(nonzero.len() > 0);
    }
}
