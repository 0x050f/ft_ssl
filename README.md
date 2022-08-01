# ft_ssl

ft_ssl is a implementation of openssl

## Compilation
```
make
```

## Usage
```
usage: ft_ssl command [flags] [file/string]
Commands:
  Message Digest Commands:
    md5
    sha256
    sha224
    sha512
    sha384
  Cipher Commands:
    base64
    des
    des-ecb
    des-cbc
Options:
  Hash Options:
    -p                 pipe STDIN to STDOUT and append the checksum to STDOUT
    -q                 quiet mode
    -r                 reverse the format of the output
    -s <string>        print the sum of the given string
  Cipher Options:
    -d                 decode/decrypt mode
    -e                 encode/encrypt mode (default)
    -i <file>          input file for message
    -o <output>        output file for message
    des only:
    -a                 decode/encode the input/output in base64, depending on the encrypt mode
    -k <key>           key in hex
    -p <password>      password in ascii
    -s <salt>          salt in hex
    -v <iv>            initialization vector in hex
```