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
  md5
  sha256
  sha512
  sha384
Options:
  -p                 pipe STDIN to STDOUT and append the checksum to STDOUT
  -q                 quiet mode
  -r                 reverse the format of the output
  -s <string>        print the sum of the given string
```