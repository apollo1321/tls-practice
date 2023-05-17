# Dumb https client

## Usage examples

```bash
# Make HTTPS GET request with specified resource
https_client -v tls1_3 --resource https://www.google.com google.com

# Make HTTP GET request with specified ciphersuites
https_client -v tls1_2 -c ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305 -r https://www.google.com  google.com

# Make HTTPS request and safe secrets in keylogfile for decryption
https_client -v tls1_2 -r https://www.google.com google.com --keylogfile key.txt

# List all avaiable ciphersuites for TLS 1.2
https_client -v tls1_2 --list

# Make HTTPS request and print verified certificate chain
https_client -v tls1_3 -r https://www.google.com google.com --chain
```
## Running with nix

```bash
# Run binary
nix --experimental-features "nix-command flakes" run github:apollo1321/tls-practice -- -r https://www.google.com/ google.com

# Build binary and store it in ./result/bin/https_client
nix --experimental-features "nix-command flakes" build github:apollo1321/tls-practice
```

## Dependencies

* [OpenSSL](https://github.com/openssl/openssl)
* [CLI11](https://github.com/CLIUtils/CLI11)
* [fmt](https://github.com/fmtlib/fmt)

## Requirements

* `cmake`
* `clang` or `gcc`
