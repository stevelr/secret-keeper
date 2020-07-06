# SecretKeeper implementation for Goole Cloud KMS

CloudKMS SecretKeeper uris are of the form
`cloudkms://PROJECT/LOCATION/KEYRING/KEY`, where

 - `PROJECT` is the google cloud kms project
 - `LOCATION` is the cloud location; use 'global' for all data centers/zones
 - `KEYRING` - your keyring name
 - `KEY` - your key name

You must set the environment variable `GOOGLE_APPLICATION_CREDENTIALS`
to the path to a credentials json file (e.g., for a service account).


## Prerequisites

- A google cloud account, with the Cloud KMS API enabled for your project
- An authorized user or service account, with the following role enabled:
  - Cloud KMS CryptoKey Encrypter/Decrypter 
- The environment variable `GOOGLE_APPLICATION_CREDENTIALS`
is set to the path of the json credentials file for the authorized account.
- Google Cloud SDK tools installed (`gcloud` is needed for the
  exapmles below)


### Create Keyring and Key, if necessary

You may use an existing keyring and key, or create one. You will need to
know the name of availability zone, or use `global` for for all zones.

- To create the keyring `my_keyring`, 

```
gcloud kms keyrings create "my_keyring" --location global
```

- To create a key `my_key` on the `my_keyring` key,

```
gcloud kms keys create my_key --keyring my_keyring --location global \
    --purpose encryption-decryption
```

# Using this keeper

The format of the keeper uri is `cloudkms:/PROJECT/LOCATION/KEYRING/KEY`,
so, the uri for our new keyring and key are
`cloudkms:/PROJECT/global/my_keyring/key`,

You can test it out with the examples/encrypt-rs command-line 
program. To encrypt `FILE` to `FILE.ENC`, use:

```
  encrypt enc -o FILE.ENC -k cloudkms:/PROJECT/global/my_keyring/my_key FILE
```

To decrypt, use

```
  encrypt dec -o FILE.DUP -k cloudkms:/PROJECT/global/my_keyring/my_key FILE.ENC
```

With default parameters, this will encrypt the file using the
LZ4XChaCha20-Poly1305 compressing cipher, 
using a newly-generated 256-bit key,
encrypt that key with `my_keyring/my_key` on Google CloudKMS, and
store the encrypted key in the header of FILE.ENC.

