# cwe-656 - Reliance on Security Through Obscurity

A simple but vulnerable application that demonstrates CWE 656 (security through obscurity) and its exploitation in practice.

## Generating the key

### Generate a random key using openssl

`export ADMIN_AES_KEY=$(openssl rand -hex 32)`

### Create a random initialization vector (IV) and prepend it to admins.enc

`IV=$(openssl rand -hex 16)`
`printf "$IV" | xxd -r -p > admins.enc`

### Append the ciphertext (AES-256-CBC over admins.csv)

`openssl enc -aes-256-cbc -K "$ADMIN_AES_KEY" -iv "$IV" -in admins.csv >> admins.enc`

### Delete admins.csv

Only keep the encrypted file (admins.enc)

## Make
### MacOS
LDFLAGS="-L$(brew --prefix openssl)/lib" CFLAGS="-I$(brew --prefix openssl)/include" make
### Other
make


## Default user

no ADMIN_AES_KEY set in env variable.
admin console refuses access.

`unset ADMIN_AES_KEY`
`./vuln-app`

## Admin user

Set the env variable ADMIN_AES_KEY to the aes key
Admin login now works

`export ADMIN_AES_KEY="the-key"`
`./vuln-app`

# The Obscurity
It's all in the debug panel
Sequence = "help" -> "status --dump" -> "open sesame" -> "!dev_override"

# original key
065aa2e0d163498e4034c0220e350732cd82d9e5cf3c17394b006d90f3cc5bf9
