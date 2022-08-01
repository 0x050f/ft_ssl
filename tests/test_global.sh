#!/bin/bash

test_commands() {
	output=$(./$exec | head -n 1 | cut -c1-6)
	assertEquals "$output" "usage:"
	output=$(./$exec abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: Error: 'abc' is an invalid command."
	output=$(./$exec abc def ghi 2>&1 | head -n 1)
}

test_arguments() {
	output=$(./$exec md5 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: md5: abc: No such file or directory"
	output=$(./$exec sha256 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: sha256: abc: No such file or directory"
	output=$(./$exec sha512 abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: sha512: abc: No such file or directory"
	output=$(./$exec base64 abc 2>&1)
	assertEquals "$output" "ft_ssl: invalid argument: 'abc'"
	output=$(./$exec des-ecb abc 2>&1)
	assertEquals "$output" "ft_ssl: invalid argument: 'abc'"
	output=$(./$exec md5 -z 2>&1)
	assertEquals "$output" "ft_ssl: invalid option -- 'z'"
	output=$(./$exec sha256 -z 2>&1)
	assertEquals "$output" "ft_ssl: invalid option -- 'z'"
	output=$(./$exec sha512 -z 2>&1)
	assertEquals "$output" "ft_ssl: invalid option -- 'z'"
	output=$(./$exec base64 -z 2>&1)
	assertEquals "$output" "ft_ssl: invalid option -- 'z'"
	output=$(./$exec des-ecb -z 2>&1)
	assertEquals "$output" "ft_ssl: invalid option -- 'z'"
}

suite_addTest test_commands
suite_addTest test_arguments
