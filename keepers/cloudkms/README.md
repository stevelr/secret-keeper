# SecretKeeper implementation for Goole Cloud KMS


## Setup

- On the Google Cloud Console, select a project, and enable the KMS API.
- Create a service account key with at least the following roles:
  - Cloud KMS CryptoKey Encrypter/Decrypter role
- Download the credentials json file and set the environment variable
  GOOGLE_ACCOUNT_CREDENTIALS to the path to that json file.
- Install the google-cloud-sdk bin tools ("gcloud")
- Create a keyring, for example "my_keyring"

```
gcloud kms keyrings create "my_keyring" --location global
```
- Create a key on that keyring, for example "my_key"

```
gcloud kms keys create my_key --keyring my_keyring --location global \
    --purpose encryption-decryption
```

# Using this keeper

The format of the keeper uri is `cloudkms:/PROJECT/LOCATION/KEYRING/KEY`,
so, using the examples above, the uri for our new keyring and key are
`cloudkms:/PROJECT/globsl/my_keyring/key`,

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
LZ4XChaCha20-Poly1305 compressing cipher using a newly-generated 256-bit
key, encrypt that key with my_keyring/my_key on Google CloudKMS, and
store the encrypted key in the header of FILE.ENC.

