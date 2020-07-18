use clap::Clap;

use secret_keeper::ciphers::CipherKind;

#[derive(Clap, Clone, Debug)]
#[clap(name = "encrypt", version)]
// derive version from Cargo.toml
pub struct Main {
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[clap(short, long, parse(from_occurrences))]
    pub verbose: u8,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, Debug)]
pub enum Command {
    /// Encrypt file
    #[clap(name = "enc")]
    Encrypt(EncryptOptions),

    /// Decrypt file
    #[clap(name = "dec")]
    Decrypt(DecryptOptions),

    #[clap(name = "key")]
    Key(Key),
}

/*
#[derive(Clap, Clone, Debug, PartialEq)]
enum CipherChoice {
    #[clap(alias = "aesgcm256", alias = "aes")]
    AesGcm256,
    #[clap(alias = "xchacha20", alias = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    #[clap(
        alias = "lz4xchacha20",
        alias = "lz4",
        alias = "lz4-xchacha20-poly1305"
    )]
    LZ4XChaCha20Poly1305,
}
*/

#[derive(Clap, Clone, Debug)]
pub struct EncryptOptions {
    /// Output file
    #[clap(short, long)]
    pub output: String,

    /// Keeper uri
    #[clap(short, long = "keeper", default_value = "env:")]
    pub keeper_uri: String,

    /// Select content encryption cipher
    #[clap(short, long = "cipher", default_value = "LZ4XChaCha20Poly1305")]
    pub cipher: CipherKind,

    /// File to decrypt
    #[clap(name = "FILE")]
    pub file: String,
}

#[derive(Clap, Clone, Debug)]
pub struct DecryptOptions {
    /// Output file
    #[clap(short, long)]
    pub output: String,

    /// Keeper uri
    #[clap(short, long = "keeper", default_value = "env:")]
    pub keeper_uri: String,

    /// File to decrypt
    #[clap(name = "FILE")]
    pub file: String,
}

#[derive(Clap, Clone, Debug)]
pub struct Key {
    #[clap(subcommand)]
    pub command: KeyCommand,
}

#[derive(Clap, Clone, Debug)]
pub enum KeyCommand {
    /// View the key
    #[clap(name = "view")]
    View(ViewKeyOptions),
}

#[derive(Clap, Clone, Debug)]
pub struct ViewKeyOptions {
    /// Encrypted file
    #[clap(name = "FILE")]
    pub file: String,
}
