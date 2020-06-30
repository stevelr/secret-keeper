# HashivaultKeeper - a SecretKeeper implementation for Hashicorp Vault

This keeper wraps the API for hashicorp vault 'transit' engine
for encryption and decryption. This api is fully asynchronous,

## Setup

If you don't already have a hashicorp vault to use,
take a look at the examples directory (examples/README.md)
which has detailed instructions for setting up 
a hashicorp vault in a docker container.

The examples/scripts folder also has some scripts that can create an
encryption key using the 'vault'
command-line program (part of the 'vault' or 'vault-bin' package for
linux distros). The HashivaultKeeper also implements an api method for
creating a new encryption key on the vault server.


## Using this keeper

 SecretKeeper uris are of the form
 - `hashivault://MYKEY`  (uses the default host:port == localhost:8200)
 - `hashivault://host:port/MYKEY`
   - this form uses http for localhost and https for all other hosts
 - `hashivault:https://host:port/MYKEY`
   - this form is only needed if the http/https scheme inferred above is not orrect

If host and port are not set in the uri, the VAULT_ADDR is checked.
VAULT_ADDR may be defined of the form 'https://127.0.0.1:8200/'.
If VAULT_ADDR is not set, 'http://127.0.0.1:8200' is used.

The REST API urls used to accesss the vault server are of the form:
```
http(s)://host:port/v1/transit/(encrypt|decrypt|keys)/<KEY_NAME>
```


You can test it out with the examples/encrypt-rs command-line 
program. Ensure that the environment variable VAULT_TOKEN is set:
```
  source secret.env
```

Then, to encrypt `FILE` to `FILE.ENC`, use:

```
  encrypt enc -o FILE.ENC -k hashivault://MYKEY FILE
```

To decrypt, use

```
  encrypt dec -o FILE.DUP -k hashivault://MYKEY FILE.ENC
```

With default parameters, this will encrypt the file using the
LZ4XChaCha20-Poly1305 compressing cipher using a newly-generated 256-bit
key, encrypt that key with MYKEY on the vault, and
store the encrypted key in the header of FILE.ENC.
