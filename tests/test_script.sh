#!/bin/bash

exec=ft_ssl
TEST_DIR=/tmp/ftest_ssl

test_des-ecb_key() {
	mkdir $TEST_DIR
	# Test encrypt
	output=$(./$exec des-ecb -k 0000000000000000 -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "$output" ""
	openssl des-ecb -d -pbkdf2 -K 0000000000000000 -in $TEST_DIR/output -out $TEST_DIR/original
	output=$(diff Makefile $TEST_DIR/original)
	output=$(./$exec des-ecb -k 0123456789abcdef -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "$output" ""
	openssl des-ecb -d -pbkdf2 -K 0123456789abcdef -in $TEST_DIR/output -out $TEST_DIR/original
	output=$(diff Makefile $TEST_DIR/original)
	output=$(./$exec des-ecb -k 0123456789abcdef -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "$output" ""
	openssl des-ecb -d -pbkdf2 -K 0123456789abcdef -in $TEST_DIR/output -out $TEST_DIR/original
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	# Test encrypt too short/long key
	output_exec=$(./$exec des-ecb -k 000000000000ff -i/bin/ls -o$TEST_DIR/output 2>&1)
	output_openssl=$(openssl des-ecb -d -pbkdf2 -K 000000000000ff -in $TEST_DIR/output -out $TEST_DIR/original 2>&1)
	assertEquals "$output_exec" "$output_openssl"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	output_exec=$(./$exec des-ecb -k 000000000000ffffff -i/bin/ls -o$TEST_DIR/output 2>&1)
	output_openssl=$(openssl des-ecb -d -pbkdf2 -K 000000000000ffffff -in $TEST_DIR/output -out $TEST_DIR/original 2>&1)
	assertEquals "$output_exec" "$output_openssl"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	# Test decrypt
	openssl des-ecb -pbkdf2 -K 0000000000000000 -in Makefile -out $TEST_DIR/output
	output=$(./$exec des-ecb -d -k 0000000000000000 -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output" ""
	output=$(diff Makefile $TEST_DIR/original)
	openssl des-ecb -pbkdf2 -K 0123456789abcdef -in Makefile -out $TEST_DIR/output
	output=$(./$exec des-ecb -d -k 0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output" ""
	output=$(diff Makefile $TEST_DIR/original)
	openssl des-ecb -pbkdf2 -K 0123456789abcdef -in /bin/ls -out $TEST_DIR/output
	output=$(./$exec des-ecb -d -k 0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output" ""
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	# Test decrypt too short/long key
	output_openssl=$(openssl des-ecb -pbkdf2 -K 000000000000ff -in /bin/ls -out $TEST_DIR/output 2>&1)
	output_exec=$(./$exec des-ecb -d -k 000000000000ff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output_exec" "$output_openssl"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	output_openssl=$(openssl des-ecb -pbkdf2 -K 000000000000ffffff -in /bin/ls -out $TEST_DIR/output 2>&1)
	output_exec=$(./$exec des-ecb -d -k 000000000000ffffff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output_exec" "$output_openssl"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	rm -rf $TEST_DIR
}

test_des-ecb_password() {
	# Test encrypt
	mkdir $TEST_DIR
	output=$(./$exec des-ecb -p abc -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "$output" ""
	openssl des-ecb -d -pbkdf2 -k abc -in $TEST_DIR/output -out $TEST_DIR/original
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "$output" ""
	output=$(./$exec des-ecb -p Passwordpassw0rdPasswordPASSWORDPasswordpassword -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "$output" ""
	openssl des-ecb -d -pbkdf2 -k Passwordpassw0rdPasswordPASSWORDPasswordpassword -in $TEST_DIR/output -out $TEST_DIR/original
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	# Test decrypt
	openssl des-ecb -pbkdf2 -k abc -in Makefile -out $TEST_DIR/output
	output=$(./$exec des-ecb -d -p abc -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "$output" ""
	openssl des-ecb -pbkdf2 -k Passwordpassw0rdPasswordPASSWORDPasswordpassword -in /bin/ls -out $TEST_DIR/output
	output=$(./$exec des-ecb -d -p Passwordpassw0rdPasswordPASSWORDPasswordpassword -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "$output" ""
	rm -rf $TEST_DIR
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

test_commands() {
	output=$(./$exec | head -n 1 | cut -c1-6)
	assertEquals "$output" "usage:"
	output=$(./$exec abc 2>&1 | head -n 1)
	assertEquals "$output" "ft_ssl: Error: 'abc' is an invalid command."
	output=$(./$exec abc def ghi 2>&1 | head -n 1)
}

. shunit2
