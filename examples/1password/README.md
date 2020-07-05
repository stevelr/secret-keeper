# Using keys in 1password with the 'env:' secret-keeper

This script shows how to use 1password with the env keeper.
(linux or macos)

You'll need the 1password 
[`op cli tool`](https://support.1password.com/command-line-getting-started/),
a bash/zsh-compatible shell, and `jq`.

Edit "signin.sh" and set MY_ACCT_NAME to the account name at 1password.

```
    # create alias that defines the op-signin shell function
    # You can add this to your ~/.bashrc (or ~/.zshrc, ...)
    source sign.sh

	# sign into 1password. You will be prompted for your vault password
	op-signin

    # let's create a password to use.
	# this command creates a new vault item 'test_key' and a random password
	# You don't have to use this, you can use an existing item 
	# as long as it has a password field named 'password'
	./onep.sh -create test_key

	# here's a command to print out the actual password
	./onep.sh test_key env | grep VAULT_PASsWORD

    # use the test_key password to encrypt a file
    ./onep.sh test_key encrypt enc -o file.enc FILE

	# decrypt it
    ./onep.sh test_key encrypt dec -o FILE.copy file.enc
```

The encrypt-rs tool (used in the example above) doesn't use the item's
password to encrypt the file directly - it derives a secure key, using a
key derivation function PBKDF2-HMAC-SHA256 to create the encryption key.

The default cipher used by the encrypt tool also uses lz4 compression,
so the encrypted size may be smaller than the original. (If the file was
already compressed or encrypted, 
the encrypted size may be slightly larger)
