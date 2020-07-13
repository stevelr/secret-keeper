# Secret-Keeper

Envelope encryption with strong cryptography and key management.
A SecretKeeper encrypts a data encryption key (DEK) with a key-encryption-key (KEK),
returning a [`WrappedKey`](https://docs.rs/secret-keeper/latest/secret_keeper/struct.WrappedKey.html).
This crate (and sub-crates) implement several SecretKeepers,
plus three content encryption ciphers:

- XCha20Cha20-Poly1305 with AEAD
- AES-GCM (256-bit)
- and a compressing cipher that combines LZ4 with XChaCha20-Poly1305


The APIs in this crate are intended to
provide good security practices while minimizing opportunities
for unintentional developer errors that could reduce the security.
One such principle is that encryption keys are always stored encrypted at rest.

Some SecretKeeper implementations have already been developed.
If you create a new one, please send me a link and I'll link to it from here.

- __Env__ generates a key from a passphrase stored in an
environment variable, using PBKDF2+HMAC+SHA256+SALT.
[EnvKeeper](https://docs.rs/secret-keeper/latest/secret_keeper/keepers/env/struct.EnvKeeper.html)

- __Prompt__ prompts the user at a terminal for a passphrase.
The KEK is generated from the passphrase using PBKDF2+HMAC+SHA256+SALT.
Requires the `secret-keeper-prompt` crate.
[PromptKeeper](https://docs.rs/secret-keeper-prompt/latest/secret_keeper_prompt/)

- __Hashivault__ Using Vault's Transit engine, the HashivaultKeeper
can create keys (key-encryption-keys) with a variety of encryption algorithms, including
`aes-gcm-256`, `ed25519`, and several others). A DEK is encrypted or decrypted by the Vault,
using the KEK managed-by and stored-on the Vault.
[Hashivault](https://crates.io/crates/secret-keeper-hashivault)

- __CloudKMS__ The CloudKmsKeeper uses keys in Google CloudKMS service.
[CloudKms](https://docs.rs/secret-keeper-cloudkms/latest/secret_keeper_cloudkms/)

- __1Password__ (linux/mac only). 1Password is included in the example directory to show how
external programs can be used with EnvKeeper and a shell script; no additional rust code
is required. Uses the free 1password
[`op cli tool`](https://support.1password.com/command-line-getting-started/),

## Implementation notes

Crypto algorithms used are implemented by other packages, notably
[RustCrypto](https://github.com/rustcrypto/), a pure-rust implemenation.

LZ4 compression is a pure rust implementation by [`lz_fear`](https://crates.io/crates/lz-fear).

The concept for this library is based on the google cloud secret-keeper library

## Status

This is a new crate and it should be considered alpha quality.

Additional SecretKeeper implementations are planned. If you create any, please let me know and
I'll link to it from here.

The core secret-keeper library compiles into wasm without error,
but I haven't tested it in a browser yet.

## Building and Testing

This crate contains sub-crates for the core
library, optional secret keeper implementations,
and a command-line encrypt program
(examples/encrypt-rs). You can build everything with `cargo build`.

The `examples/encrypt-rs` folder contains some shell scripts 
for testing the `encrypt` cli program with various secret keepers.
The binary can be installed independently with `cargo install encrypt-rs`.

### Testing hashivault

To run hashivault tests, you will need an installed instance of
hashiorp vault. 
 
To set up and iniitalize a vault instance in a docker container,
for development and testing, run these three commands:

```sh
examples/hashivault/scripts/create-vault-docker.sh
examples/hashivault/scripts/make-app-token.sh
source examples/hashivault/secret.env
```

The last command sets the `VAULT_TOKEN` environment variable,
which is required to run hashivault keeper tests and 
other `vault` cli commands. The file `examples/hashivault/README.md`
contains additional information about these scripts.

### Testing cloudkms

See keepers/cloudkms/README.md for instructions on testing the cloudkms
keeper.

