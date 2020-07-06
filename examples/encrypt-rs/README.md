## Command-line envelope encryption with secret-keeper

Encryption and decryption using 
[Secret Keeper](https://crates.io/crates/secret-keeper) 

### Install

```cargo install encrypt-rs```

### Run

```sh
  # Encrypt file
  $ encrypt enc -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE

  # Decrypt file
  $ encrypt dec -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE

  # View key envelope
  $ encrypt key view   [ -k KEEPER ] FILE
```

__-k KEEPER__ options: (default: 'env:')
- `env:` (EnvKeeper)
  - `env:`  - passphrase for deriving key is in environment var VAULT_PASSWORD.
  - `env:VARNAME` - passphrase for deriving key is in environment variable VARNAME
  ```
   # example:
   export PASSWORD="my-super-secret-passphrase"
   encrypt enc -o FILE.enc -k env:PASSWORD FILE
   ```
- `prompt:` (PromptKeeper)
  - user will be prompted on terminal for passphrase for deriving key
- `hashivault:` (HashivaultKeeper)
  - key-encrypting-key is on hashivault transit server. See 
  [hashivault keeper](https://docs.rs/secret-keeper-hashivault) doc for url syntax
  ```
  # example:
  encrypt enc -o FILE.enc -k hashivault://my_key FILE
  ```
- `cloudkms:` (CloudKMSKeeper)
  ```
  # example:
  encrypt enc -o FILE.enc -k cloudkms:/PROJ/global/my_keyring/my_key FILE
  ```



__-c CIPHER__ options:
Default cipher is LZ4XChaCha20Poly1305, which combines LZ4
compression with XChaCha20-Poly1305. (Cipher algorithm 
implemented by
[RustCrypto](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)
 - `XChaCha20Poly1305` (aliases: `xchacha20`, `xchacha20poly1305`)
 - `LZ4XChaCha20Poly1305` (aliases: `lz4`, `lz4xchacha20`, `lz4xchacha20poly1305`)
 - `AesGcm256` (aliases: `aes`, `aesgcm`, `aesgcm256`)


_There are some additional usage examples in the test* shell scripts._

### Random number generation

File nonces and keys are generated with the platform's OS CSRNG,
using the [rand](https://crates.io/crates/rand) crate.


