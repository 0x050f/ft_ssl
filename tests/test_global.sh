#!/bin/bash

test_commands() {
	output=$(./$exec | head -n 1 | cut -c1-6)
	assertEquals "usage:" "$output"
	output=$(./$exec abc 2>&1 | head -n 1)
	assertEquals "ft_ssl: Error: 'abc' is an invalid command." "$output"
	output=$(./$exec abc def ghi 2>&1 | head -n 1)
}

test_arguments() {
	output=$(./$exec md5 abc 2>&1 | head -n 1)
	assertEquals "ft_ssl: md5: abc: No such file or directory" "$output"
	output=$(./$exec sha256 abc 2>&1 | head -n 1)
	assertEquals "ft_ssl: sha256: abc: No such file or directory" "$output"
	output=$(./$exec sha512 abc 2>&1 | head -n 1)
	assertEquals "ft_ssl: sha512: abc: No such file or directory" "$output"
	output=$(./$exec base64 abc 2>&1)
	assertEquals "ft_ssl: invalid argument: 'abc'" "$output"
	output=$(./$exec des-ecb abc 2>&1)
	assertEquals "ft_ssl: invalid argument: 'abc'" "$output"
	output=$(./$exec md5 -z 2>&1)
	assertEquals "ft_ssl: invalid option -- 'z'" "$output"
	output=$(./$exec sha256 -z 2>&1)
	assertEquals "ft_ssl: invalid option -- 'z'" "$output"
	output=$(./$exec sha512 -z 2>&1)
	assertEquals "ft_ssl: invalid option -- 'z'" "$output"
	output=$(./$exec base64 -z 2>&1)
	assertEquals "ft_ssl: invalid option -- 'z'" "$output"
	output=$(./$exec des-ecb -z 2>&1)
	assertEquals "ft_ssl: invalid option -- 'z'" "$output"
}

suite_addTest test_commands
suite_addTest test_arguments
