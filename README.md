# edsync: HTTP sync tool for signed files

## Features

* ed25519 elliptic curve signature

* 256-bit SHA3 file hashes

* Minimal dependencies: The Windows build needs system dlls only; uses WinHTTP for connection. On Linux the only dependencies are `libcurl` and `openssl`.

* Stores files in a catalog where each line contains a filename and a SHA3 hash. Catalog files are compatible with Total Commander: hitting `enter` on a `.sha3` catalog file checks the hashes.

* All-or-nothing update: no partial update is applied. Files first written with a post-fix `.edsync-pending`

* On sync, file locks are checked and the user is notified to unlock the files; once the files are not locked the update process continues.

## Command reference

### `edsync keygen` (ran by distributor)

Create a public+private key-pair HOME directory: `.edsync-signer-keypair`

### `edsync update-catalog` (ran by distributor)

* create `edsync-catalog.sha3`, containing the SHA3 hashes of all files under the current directory (ignores files specified in `.edsyncignore`)

* create `edsync-catalog.sig`, the signature for `edsync-catalog.sha3` based on the private key in `HOME\.edsync-signer-keypair`

### `edsync make-source-json [url]` (ran by distributor)

Convenience command for creating `edsync-source.json`, a file that contains a public key & URL. `edsync-source.json` has to be distributed to clients along with the `edsync` executable.

```json
{
    "public_key": "distributor's public key",
    "url": "http://update-source-url/"
}
```

### `edsync verify`

Verify the signature of the catalog and file hashes based on `edsync-catalog.sha3`

### `edsync` without parameters (ran by clients)

Running `edsync` without parameters trigger an update based on `edsync-source.json`:

- download the catalog based on the URL in `edsync-source.json`

- verify the catalog based on the public key in `edsync-source.json`

- download files from the URL if local hashes are different from ones in remote `edsync-catalog.sha3`

## Initial workflow

1. [distributor] `edsync keygen` *need to be done only once*

2. [distributor] `edsync update-catalog`

3. [distributor] `edsync make-source-json http://update-source-url/`

4. [distributor] upload files to `http://update-source-url/` (files in the catalog, `edsync-catalog.sha3`, `edsync-catalog.sig`)

5. [distributor] send `edsync` executable & `edsync-source.json` to clients

6. [client] `edsync`

## Shipping an update

1. [distributor] `edsync update-catalog`
2. [distributor] upload files
3. [client] run `edsync`
