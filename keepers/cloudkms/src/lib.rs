//! SecretKeeper for Google Cloud KMS
//!
//! SecretKeeper uris are of the form
//! - `cloudkms://PROJECT/LOCATION/KEYRING/KEY`
//!
//! - PROJECT is the google cloud kms
//! - LOCATION is the cloud location; use 'global' for all data centers
//! - KEYRING - your keyring name
//! - KEY - your key name
//!
//! You also need to set the environment variable GOOGLE_APPLICATION_CREDENTIALS
//! to point to the service account credentials json file.
//!
use async_trait::async_trait;
use bytes::Bytes;
use googapis::{
    google::cloud::kms::v1::{
        crypto_key::CryptoKeyPurpose::EncryptDecrypt,
        key_management_service_client::KeyManagementServiceClient, CreateCryptoKeyRequest,
        CryptoKey, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    },
    CERTIFICATES,
};
use gouth::Token;
use secret_keeper::{
    error::{Error, Result},
    keepers::{Create, SecretKeeper},
    util::{form_get, FromBech32, ToBech32},
    WrappedKey,
};
use serde_urlencoded;
use std::fmt;
use tonic::{
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig},
    Request,
};
use url::Url;

const URI_SCHEME: &str = "cloudkms";
const CLOUDKMS_ENDPOINT: &str = "https://cloudkms.googleapis.com";
const CLOUDKMS_DOMAIN: &str = "cloudkms.googleapis.com";

/// SecretKeeper implementation that uses Google Cloud KMS for key storage
pub struct CloudKmsKeeper {
    token: Token,
}

unsafe impl Sync for CloudKmsKeeper {}

/// Implement Display that skips Token
impl fmt::Display for CloudKmsKeeper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CloudKmsKeeper")
    }
}

/// Implement Debug that skips Token
impl fmt::Debug for CloudKmsKeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CloudKmsKeeper")
    }
}

/// Options for initializing CloudKmsKeeper.Currently there are no options.
pub struct CloudKmsOptions {}

impl CloudKmsOptions {
    pub fn defaults() -> Self {
        CloudKmsOptions {}
    }
}

impl CloudKmsKeeper {
    /// Constructs a new Google Cloud KMS keeper with default options
    pub async fn new_default() -> Result<Self, Error> {
        Ok(Self::new(CloudKmsOptions::defaults()).await?)
    }

    /// Constructs a new google CloudKMS keeper
    pub async fn new(_opt: CloudKmsOptions) -> Result<Self, Error> {
        // the only supported auth method is with credentials file.
        // Catch most likely error first
        if std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_err() {
            return Err(Error::OtherError("CloudKmsKeeper requires environment variable GOOGLE_APPLICATION_CREDENTIALS to be set".to_string()));
        }
        let token = Token::new()
            .map_err(|e| Error::OtherError(format!("CloudKmsKeeper failed to initialize due to token auth error: ({}). GOOGLE_APPLICATION_CREDENTIALS must have the correct path of the credentials json file",
                        e.to_string())))?;
        Ok(CloudKmsKeeper { token })
    }

    /// register with SecretKeeper so it can be discovered with SecretKeeper::for_uri
    pub async fn register(self) -> Result<(), Error> {
        Ok(SecretKeeper::register(Box::new(self)).await?)
    }

    async fn service_connect(&self) -> Result<KeyManagementServiceClient<Channel>, Error> {
        let token_header = self.token.header_value().unwrap();
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(CERTIFICATES))
            .domain_name(CLOUDKMS_DOMAIN);
        let channel = Channel::from_static(CLOUDKMS_ENDPOINT)
            .tls_config(tls_config)
            .connect()
            .await
            .map_err(|e| Error::OtherError(format!("Service error: {}", e.to_string())))?;
        let service =
            KeyManagementServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
                let meta = MetadataValue::from_str(&token_header).unwrap();
                req.metadata_mut().insert("authorization", meta);
                Ok(req)
            });
        Ok(service)
    }
}

/// convert keeper uri to kms location id
/// in : /PROJECT/LOCATION/KEYRING/KEY
/// out: [ PROJECT, LOCATION, KEYRING, KEY]
/// out: projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY",
fn path_split(uri: &str, expect: usize) -> Result<Vec<String>, Error> {
    let url =
        Url::parse(uri).map_err(|e| Error::OtherError(format!("uri parse failed: {:?}", e)))?;
    if url.scheme() != URI_SCHEME {
        return Err(Error::InvalidParameter(format!(
            "Invalid uri scheme, expecting {}",
            URI_SCHEME
        )));
    }
    let path = url.path();
    let mut parts: Vec<String> = path.split("/").map(|s| s.to_string()).collect();
    if !path.starts_with("/") || parts.len() != expect + 1 {
        return Err(Error::OtherError(format!(
            "Invalid path in keeper uri. Expecting /PROJECT/LOCATION/KEYRING{}",
            if expect == 4 { "/KEY" } else { "" }
        )));
    }
    parts.remove(0);
    Ok(parts)
}

fn key_path(uri: &str) -> Result<String, Error> {
    let parts = path_split(uri, 4usize)?;
    Ok(format!(
        "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
        parts[0], parts[1], parts[2], parts[3]
    ))
}

fn keyring_path(uri: &str) -> Result<String, Error> {
    let parts = path_split(uri, 3usize)?;
    Ok(format!(
        "projects/{}/locations/{}/keyRings/{}",
        parts[0], parts[1], parts[2]
    ))
}

#[async_trait]
impl<'a> SecretKeeper for CloudKmsKeeper {
    /// Sends key to cloud to be encrypted.
    /// key-encryption-key never leavs the Hashicorp vault.
    /// Returned encrypted key is a string
    async fn wrap(&self, uri: &str, _nonce: &[u8], key: &[u8]) -> Result<WrappedKey, Error> {
        let mut service = self.service_connect().await?;
        let resp: EncryptResponse = service
            .encrypt(Request::new(EncryptRequest {
                name: key_path(uri)?,
                plaintext: key.to_vec(),
                additional_authenticated_data: Vec::new(),
            }))
            .await
            .map_err(|e| Error::OtherError(format!("Service error: {}", e.to_string())))?
            .into_inner();

        Ok(WrappedKey {
            key_enc: resp.ciphertext.to_bech32(),
            key_uri: String::from(uri),
            ident: None,
        })
    }

    /// Sends key to hashicorp vault to be decrypted.
    /// key-encryption-key never leavs the Hashicorp vault.
    async fn unwrap(&self, _nonce: &[u8], wk: &WrappedKey) -> Result<Bytes, Error> {
        let mut service = self.service_connect().await?;
        let dec: DecryptResponse = service
            .decrypt(Request::new(DecryptRequest {
                name: key_path(&wk.key_uri)?,
                ciphertext: wk.key_enc.from_bech32()?,
                additional_authenticated_data: Vec::new(),
            }))
            .await
            .map_err(|e| (Error::OtherError(format!("Service error: {}", e.to_string()))))?
            .into_inner();
        Ok(Bytes::from(dec.plaintext.to_owned()))
    }

    /// Returns the scheme 'hashivault'
    fn get_scheme(&self) -> &str {
        URI_SCHEME
    }

    /// Returns instance of Create
    fn as_create(&self) -> Result<&dyn Create, Error> {
        Ok(self)
    }
}

#[async_trait]
impl Create for CloudKmsKeeper {
    /// Creates the key.
    /// `key_name` is any valid key name
    /// `params` are url-encoded parameters that can be created with
    /// [`serde_urlencoded`](https://docs.rs/serde_urlencoded/0.6.1/serde_urlencoded/fn.to_string.html)
    ///
    /// Params:
    ///   - 'parent' : /PROJECT/LOCATION/KEYRING
    ///
    async fn create_key(&'_ self, key_name: &str, params: &str) -> Result<(), Error> {
        let fields = serde_urlencoded::from_str(params).map_err(|e| {
            Error::InvalidParameter(format!("'params' is not valid urlencoded: {}", e))
        })?;
        let location = keyring_path(match form_get(&fields, "parent") {
            Some(val) => val,
            None => {
                return Err(Error::InvalidParameter(
                    "'parent' must be defined in params".to_string(),
                ))
            }
        })?;
        let mut service = self.service_connect().await?;
        let _ = service
            .create_crypto_key(Request::new(CreateCryptoKeyRequest {
                parent: location,
                crypto_key_id: String::from(key_name),
                crypto_key: Some(CryptoKey {
                    purpose: EncryptDecrypt.into(),
                    ..Default::default()
                }),
                skip_initial_version_creation: false,
            }))
            .await
            .map_err(|e| (Error::OtherError(format!("Service error: {}", e.to_string()))))?;
        Ok(())
    }
}
