// src/vault_client.rs
// async http api client for hashicorp vault

use base64;
use http;
use reqwest;
use secret_keeper::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

/// environment variable used to store token, (if not provided in keeper uri)
pub(crate) const VAULT_TOKEN: &str = "VAULT_TOKEN";
/// environment variable used to hold vault address, if not provided in keeper uri
pub(crate) const VAULT_ADDR: &str = "VAULT_ADDR";
/// fallback for VAULT_ADDR if not defined (without trailing slash)
pub(crate) const DEFAULT_VAULT_ADDR: &str = "http://127.0.0.1:8200";

/// default hashicorp listen port - can be overridden in keeper uri
const DEFAULT_PORT: u16 = 8200;
/// keeper uri prefix
pub const URL_SCHEME: &str = "hashivault";
///
/// url paths used in this api
const TRANSIT_ENCRYPT_URL: &str = "/v1/transit/encrypt/";
const TRANSIT_DECRYPT_URL: &str = "/v1/transit/decrypt/";
const TRANSIT_KEY_URL: &str = "/v1/transit/keys/";
const TOKEN_RENEW_URL: &str = "/v1/auth/token/renew/";

#[doc(internal)]
#[derive(Debug)]
/// Metadata extracted from keeper uri, used to generate http header and urls for vault client api
pub struct ClientSpec {
    pub uri: String,
    pub base_url: String,
    pub key_name: String,
    pub token: String,
}

#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
/// Structure used for Create key request
struct CreateKeyReq {
    // valid key types: https://www.vaultproject.io/api-docs/secret/transit#type
    // examples: 'aes256-gcm96', 'ed25519', 'ecdsa-p384'
    r#type: String,
}

#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
/// Structure used for Decrypt-Request and Encrypt-Response
pub struct CipherResp {
    data: CipherData,
}

/// Structure used for Decrypt-Request and Encrypt-Response
#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CipherData {
    ciphertext: String,
}
/// Structure used for Encrypt-Request and Decrypt-Response
#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
pub struct PlainResp {
    data: PlainData,
}

/// Structure used for Encrypt-Request and Decrypt-Response
#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
pub struct PlainData {
    plaintext: String,
}

/// Structure used to enable deletion on key
#[doc(internal)]
#[derive(Debug, Deserialize, Serialize)]
pub struct DeletionConfig {
    deletion_allowed: bool,
}

/// concatenate strings
#[doc(internal)]
macro_rules! strcat {
    ( $( $x:expr ),* ) => {
        {
            let mut s = String::from("");
            $(
                s.push_str($x);
            )*
            s
        }
    };
}

/// Create new vault http client for api requests with the given api token
pub fn new_client(token: &String) -> Result<reqwest::Client, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    let _ = headers.insert(
        "X-Vault-Token",
        http::HeaderValue::from_str(token)
            .map_err(|_| Error::InvalidParameter("invalid token string".to_string()))?,
    );

    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|_| Error::InvalidParameter("invalid token string".to_string()))?)
}

/// Send POST request to vault server and parse json response
/// Returns error if there are any IO errors OR if http status is not 2xx
pub async fn post_json<'c, REQ, RESP>(
    client: &reqwest::Client,
    url: String,
    body: REQ,
) -> Result<RESP, Error>
where
    REQ: Serialize + std::fmt::Debug,
    RESP: for<'de> serde::de::Deserialize<'de>,
{
    let res = post(client, url, body)
        .await?
        .json::<RESP>()
        .await
        .map_err(|e| {
            Error::OtherError(format!("Invalid json response from vault server: {:?}", e))
        })?;
    Ok(res)
}

/// Send POST request to vault server, returning http response
/// Returns error if there are any IO errors OR if http status is not 2xx
pub async fn post<REQ>(
    client: &reqwest::Client,
    url: String,
    body: REQ,
) -> Result<reqwest::Response, Error>
where
    REQ: Serialize + std::fmt::Debug,
{
    let res = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::OtherError(format!("Vault server IO error: {:?}", e)))?;
    if !res.status().is_success() {
        eprintln!(
            "vault request error status {:?} url {}\nclient: {:#?}\nbody: {:#?}\nresponse: {:#?}",
            res.status(),
            &url,
            &client,
            &body,
            &res
        );
        return Err(Error::OtherError(format!(
            "Vault server api error: {:?}",
            res.error_for_status()
        )));
    }
    Ok(res)
}

/// Create a new transit key.
/// Returns error if there are any IO errors OR if http status is not 2xx
/// currently only used for tests
pub async fn create_key(spec: &ClientSpec, key_type: &str) -> Result<(), Error> {
    // TODO: key_type should be an enum
    let client = new_client(&spec.token)?;
    let url = format!("{}{}{}", spec.base_url, TRANSIT_KEY_URL, spec.key_name);
    let _ = post(
        &client,
        url,
        CreateKeyReq {
            r#type: String::from(key_type),
        },
    )
    .await?;
    Ok(())
}

/// Renew a token
pub async fn renew_token(spec: &ClientSpec) -> Result<(), Error> {
    let client = new_client(&spec.token)?;
    let url = format!("{}{}{}", spec.base_url, TOKEN_RENEW_URL, &spec.token);
    let _ = post(&client, url, {}).await?;
    Ok(())
}

/// Encrypt the plaintext data using transit api, using key hosted on vault server
/// Returns data as string of the form: vault:v1:<base64-encoded-data>
pub async fn encrypt(spec: &ClientSpec, plaintext: &[u8]) -> Result<String, Error> {
    let client = new_client(&spec.token)?;
    let res: CipherResp = post_json(
        &client,
        strcat!(&spec.base_url, TRANSIT_ENCRYPT_URL, &spec.key_name),
        PlainData {
            plaintext: base64::encode(plaintext),
        },
    )
    .await?;
    Ok(res.data.ciphertext)
}

/// Decrypts the data using transit api, using key hosted on vault server
/// Input data is of the form "vault:v1:<base64-encoded-data>"
/// Returns Vec<u8>
pub async fn decrypt(spec: &ClientSpec, ciphertext: String) -> Result<Vec<u8>, Error> {
    let client = new_client(&spec.token)?;
    let res: PlainResp = post_json(
        &client,
        strcat!(&spec.base_url, TRANSIT_DECRYPT_URL, &spec.key_name),
        CipherData { ciphertext },
    )
    .await?;
    let bindata = base64::decode(res.data.plaintext)
        .map_err(|_| Error::OtherError(String::from("response had invalid base64")))?;
    Ok(bindata)
}

/// Send key delete request to vault server, returning http response
/// Returns error if there are any IO errors
#[allow(dead_code)]
pub async fn delete_key(spec: &ClientSpec) -> Result<(), Error> {
    let client = new_client(&spec.token)?;
    let url = format!("{}{}{}", spec.base_url, TRANSIT_KEY_URL, spec.key_name);

    // two api calls are required to delete a key:
    //   the deletion_allowed must be set on the key's endpoint
    //   then deletion may be called
    let key_config_url = strcat!(&url, "/config");
    let _ = post(
        &client,
        key_config_url,
        DeletionConfig {
            deletion_allowed: true,
        },
    )
    .await?;

    let _ = client
        .delete(&url)
        .send()
        .await
        .map_err(|e| Error::OtherError(format!("Vault server IO error: {:?}", e)))?
        .error_for_status()
        .map_err(|e| Error::OtherError(format!("Vault server api delete error: {:?}", e)))?;
    Ok(())
}

/// extract query parameter from url.
///   Example: url "http://server/path?foo=bar", foo => "bar"
/// Returns None if token is undefined or empty
fn get_query_value(url: &Url, key: &str) -> Option<String> {
    for (k, v) in url.query_pairs() {
        if k == key && v.len() > 0 {
            return Some(String::from(v.as_ref()));
        }
    }
    None
}

pub fn get_base_url() -> String {
    env::var(VAULT_ADDR)
        .map(|s| String::from(remove_trailing_slash(&s)))
        // not in env, fallback to default
        .unwrap_or(String::from(DEFAULT_VAULT_ADDR))
}

impl ClientSpec {
    /// Parse uri into client spec
    ///
    /// Url format must be in one of the following formats*:
    ///
    ///   - `hashivault://key`
    ///     If this format is used, scheme, host, and port are
    ///     found from environment variable VAULT_ADDR, or, if VAULT_ADDR is undefined,
    ///     the defaults used are http://127.0.0.1:8200
    ///   - `hashivault://host:port/key`
    ///     If this format is used, host and port override any possible value of
    ///     VAULT_ENV, and scheme is inferred from the host. If host is `localhost`
    ///     or `127.x.x.x`, scheme is `http`, otherwise it is `https`
    ///   - hashivault:http://host:port/key
    ///     This uri format explicitly overrides scheme, host, and port.
    ///
    /// (*) The token must also be provided, either by appending ?token=VALUE
    ///   to one of the uri forms above, or by setting the environment var VAULT_TOKEN.
    ///
    pub fn from_uri(uri: &str) -> Result<ClientSpec, Error> {
        let mut url =
            Url::parse(uri).map_err(|e| Error::OtherError(format!("Invalid uri: {}", e)))?;
        if url.scheme() != URL_SCHEME {
            return Err(Error::InvalidParameter(format!(
                "Invalid keeper uri {}, must begin with '{}:'",
                uri, URL_SCHEME,
            )));
        }

        // for third format ("hashivault:http..."), parse path again
        if url.path().starts_with("http") && url.host_str().is_none() {
            url = Url::parse(url.path())
                .map_err(|_| Error::InvalidParameter("Invalid keeper uri".to_string()))?;
        }

        let base_url = if url.host_str().is_some() && url.path().len() > 0 {
            // host was specified in uri,
            // so we'll use uri (or defaults) for scheme, host, and port
            let host = url.host_str().unwrap();
            let scheme = match url.scheme() {
                "hashivault" => {
                    // these default schemes can always be overridden with third format above
                    if host == "localhost" || host.starts_with("127.") {
                        "http"
                    } else {
                        "https"
                    }
                }
                s => s,
            };
            let port: u16 = match url.port() {
                Some(p) => p,
                None => DEFAULT_PORT,
            };
            format!("{}://{}:{}", scheme, host, port)
        } else {
            get_base_url()
        };

        let mut key_name = if url.path() == "" {
            // no host:port specified, url was hashivault://KEY_NAME
            match url.host_str() {
                Some(k) => k,
                None => return Err(Error::InvalidParameter("Invalid keeper uri".to_string())),
            }
        } else {
            url.path()
        };
        key_name = remove_leading_slash(key_name);
        if key_name.len() == 0 {
            return Err(Error::InvalidParameter(
                "uri missing key name, for example 'hashivault://KEY_NAME'".to_string(),
            ));
        }

        // look for 'token=' query parameter, or look in environment if not in url
        let token = match get_query_value(&url, "token") {
            Some(v) => v,
            None => env::var(VAULT_TOKEN).unwrap_or(String::from("")),
        };
        // handle cases where query param or env var is defined, but empty
        if token.len() == 0 {
            return Err(Error::InvalidParameter(
                "Keeper uri did not contain token query parameter, and the environment variable VAULT_TOKEN is undefined"
                    .to_string(),
            ));
        }

        Ok(ClientSpec {
            uri: String::from(uri),
            base_url,
            key_name: String::from(key_name),
            token,
        })
    } // from_uri
} // impl ClientSpec

fn remove_trailing_slash(s: &str) -> &str {
    if s.ends_with("/") {
        &s[..(s.len() - 1)]
    } else {
        s
    }
}

fn remove_leading_slash(s: &str) -> &str {
    if s.starts_with("/") {
        &s[1..]
    } else {
        s
    }
}
