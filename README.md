# age-plugin-op

An [age](https://age-encryption.org) plugin for 1Password CLI integration.

## Installation

```bash
go install bou.ke/age-plugin-op@latest
```

Make sure the binary is in your `$PATH` so that age can find it.

## Usage

Run age with `-j op` to decrypt secrets using SSH Keys from 1Password.

You can also run `age-plugin-op` to get an identity file you can pass to age.

### Files

- `main.go` - Entry point that sets up the plugin and handles the age plugin protocol
- `plugin.go` - Implements the Recipient and Identity types for encryption/decryption

## License

TBD
