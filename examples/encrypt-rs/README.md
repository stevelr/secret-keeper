# Command-line envelope encryption with secret-keeper

This program provides encryption and decryption
using 
[Secret Keeper](https://crates.io/crates/secret-keeper) 

Encrypt a file with choice of SecretKeeper

- Environment
- Prompt
- Hashicorp Vault
- Google Cloud KMS

and choice of encrypting cipher

- AES-GCM-256
- XChaCha20-Poly1305
- LZ4XChaCha20-Poly1305, a compressing cipher.

## Syntax:

```
  # Encrypt file
  $ encrypt enc -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE

  # Decrypt file
  $ encrypt dec -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE

  # View key envelope
  $ encrypt key view   [ -k KEEPER ] FILE
```


## Keeper URIs

If a secret keeper uri is not specified, default `env:` is used.

Secret keepers:

- `env:`  - passphrase for deriving key is in environment var VAULT_PASSWORD
- `env:VARNAME` - passphrase for deriving key is in environment variable VARNAME
- `prompt:` - user will be prompted on terminal for passphrase for deriving key
- `hashivault:...`        - key-encrypting-key is on hashivault transit server.
  See [hashivault keeper](https://docs.rs/secret-keeper-hashivault) doc for url syntax

- `cloudkms:...`  - Google Cloud KMS

## Ciphers

Default cipher is LZ4XChaCha20Poly1305, which combines LZ4
compression with XChaCha20-Poly1305. (Cipher algorithm 
implemented by
[RustCrypto](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)

Cipher options (-c flag):

 - XChaCha20Poly1305 (aliases: xchacha20, xchacha20poly1305)
 - LZ4XChaCha20Poly1305 (aliases: lz4, lz4xchacha20, lz4xchacha20poly1305)
 - AesGcm256 (aliases: aes, aesgcm, aesgcm256)

## Random number generation

File nonces and keys are generated with the platform's OS CSRNG,
using the [rand](https://crates.io/crates/rand) crate.

## Building

`cargo build`

If you build from source, the binary should be in 
secret-keeper/target/{debug,release}/encrypt

