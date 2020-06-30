
gcloud kms keyrings create "my_keyring" --location global                                 git:(master|…


:w
gcloud kms keys create my_key --keyring my_keyring --location global
--purpose encryption-decryption

package that creates jwt
  https://github.com/durch/rust-goauth

gcp auth
  - https://lib.rs/crates/gcp_auth
  - uses env var to point to credentials.json file


- create service account key
  - name "secret-keeper"
  - role "service account user"
  - type JSON

- enable KMS api
- add Cloud KMS CryptoKey Encrypter/Decrypter role
- add Cloud KMS Admin (do I need that?)
