# Secret-Keeper

Envelope encryption with strong cryptography and key management.
A SecretKeeper encrypts a data encryption key (DEK) with a key-encryption-key (KEK),
returning a `WrappedKey`.

Encryption ciphers used include
256-bit AES-GCM and Cha20Cha20-Poly1305 with AEAD,
and a compressing cipher combining lz4 compression with
chacha20-poly1305.

The APIs in this crate are intended to
provide good security practices while minimizing opportunities
for unintentional developer errors that could reduce the security.
One such principle is that encryption keys are always stored encrypted at rest.

Several SecretKeeper implementations have already been developed.
If you create a new one, please send me a link and I'll link to it from here.

- __Env__ generates a key from a passphrase stored in an
environment variable, using PBKDF2+HMAC+SHA256+SALT.

- __Prompt__ prompts the user at a terminal for a passphrase.
The KEK is generated from the passphrase using PBKDF2+HMAC+SHA256+SALT.
Requires the `secret-keeper-prompt` crate.

- __Hashivault__ Using Vault's Transit engine, the HashivaultKeeper
can create keys (key-encryption-keys) with a variety of encryption algorithms, including
`aes-gcm-256`, `ed25519`, and several others). A DEK is encrypted or decrypted by the Vault,
using the KEK managed-by and stored-on the Vault.

- __Cloud KMS__ Uses Google Cloud KMS to create keys and encrypt and
  decrypt content.

- __1Password__ (linux only). 1Password is included in the example directory to show how
external programs can be used with EnvKeeper and a shell script; no additionl rust code
is required. Requires the free `op` program developed by the 1password team.


## Implementation notes

Crypto algorithms used are implemented by other packages, notably
[RustCrypto](https://github.com/rustcrypto/), a pure-rust implemenation.

The compressing cipher uses lz4 implementation by 
[`lz_fear`] (pure rust).

All code in the core crate is pure rust and can be compiled to wasm.
Some of the secret keeper implementations have other dependencies.

The concept for this library is based on the google cloud secret-keeper library

## Status

This is a new crate and it should be considered alpha quality.

The code compiles to wasm but I haven't tested it in browser yet.

