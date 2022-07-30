#!/bin/bash

exec=ft_ssl

test_options() {
	output=$(./$exec md5 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: md5: abc: No such file or directory"
	output=$(./$exec sha256 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: sha256: abc: No such file or directory"
	output=$(./$exec sha512 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: sha512: abc: No such file or directory"
	output=$(./$exec base64 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: invalid argument: 'abc'"
	output=$(./$exec des-ecb abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: invalid argument: 'abc'"
}

test_args() {
	output=$(./$exec | head -n 1 | cut -c1-6)
	assertEquals "$output" "usage:"
	output=$(./$exec abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: Error: 'abc' is an invalid command."
	output=$(./$exec abc def ghi 2>&1 | head -n 1)
}

. shunit2
