# Vault Dump

## Description

Dumps and restores secrets from Hashicorp Vault into GPG2 encrypted JSON files.

### Supported secret mount types

  - KV (v1)
  - KV (v2)
  - Transit

## Usage

For help, run `./vault_dump --help`

```text
Dump and restore secrets from Hashicorp Vault

Usage:
  vault_dump [flags]
  vault_dump [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  dump        Dump Vault to an encrypted JSON file
  help        Help about any command
  restore     Restore an encrypted JSON dump to Vault

Flags:
  -x, --debug     enable debug output
  -h, --help      help for vault_dump
  -j, --json      print logs in JSON format
  -v, --version   show vault_dump version

Use "vault_dump [command] --help" for more information about a command.
```

### Dump prerequisites

To dump, you need to ensure you have the following:

  - Network access to your Vault instance, with the `VAULT_ADDR` environment
    variable defined.
  - To be authenticated with Vault (uses `VAULT_TOKEN` environment variable
    or `.vault-token` file in your home directory).
  - An GPG2 key that you have the private key for, you only need the public key
    to encrypt, however to decrypt you will need the corresponding private key.
  - Permission to list and read secrets, sample policy below:

    ```hcl
    path "*" {
        capabilities = ["read", "list"]
    }
    ```

Example command using a public key:

```bash
$ ./vault_dump \
    dump \
    --file="$(date +%s).json.asc" \
    --key=me@email.com.pub  # This is a public key
```

Example command using a private key:

```bash
$ ./vault_dump \
    dump \
    --file="$(date +%s).json.asc" \
    --passphrase="yo_r-Str0ng-Pa55-phRaSe" \ # This can also be specified with VAULT_DUMP_PASSPHRASE environment variable
    --key=me@email.com.asc  # This is a private key
```

### Restore prerequisites

To restore a dump, you will need the following:

  - Network access to your Vault instance, with the `VAULT_ADDR` environment
    variable defined.
  - To be authenticated with Vault (uses `VAULT_TOKEN` environment variable
    or `.vault-token` file in your home directory).
  - The secret portion of the GPG key used to encrypt the dump.
  - The passphrase for the GPG key secret.
  - Mount points to already be present in Vault (`vault_dump` will not
    yet re-create mount points).
  - Write access to each mount.

Example command:

```bash
$ ./vault_dump \
    restore \
    --file="somedump.json.asc" \
    --passphrase="yo_r-Str0ng-Pa55-phRaSe" \ # This can also be specified with VAULT_DUMP_PASSPHRASE environment variable
    --key=me@email.com.asc  # This is a private key
```

### Container image

You can download the container image from hub.docker.com:

```bash
$ docker pull xanmanning/vault-dump:latest
$ podman pull docker.io/xanmanning/vault-dump:latest
```

## License

[BSD 3-Clause](LICENSE)
