#!/bin/bash

SUFFIX="-provider legacy -provider default"

test_des-ecb_key() {
	mkdir -p $TEST_DIR
	# Test encrypt
	output=$(./$exec des-ecb -k 0000000000000000 -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -K 0000000000000000 -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(./$exec des-ecb -k 0123456789abcdef -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -K 0123456789abcdef -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(./$exec des-ecb -k 0123456789abcdef -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -K 0123456789abcdef -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test encrypt too short/long key
	output_exec=$(./$exec des-ecb -k 000000000000ff -i/bin/ls -o$TEST_DIR/output 2>&1)
	output_openssl=$(openssl des-ecb -d -pbkdf2 -K 000000000000ff -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX 2>&1)
	assertEquals "$output_openssl" "$output_exec"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	output_exec=$(./$exec des-ecb -k 000000000000ffffff -i/bin/ls -o$TEST_DIR/output 2>&1)
	output_openssl=$(openssl des-ecb -d -pbkdf2 -K 000000000000ffffff -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX 2>&1)
	assertEquals "$output_openssl" "$output_exec"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test decrypt
	openssl des-ecb -pbkdf2 -K 0000000000000000 -in Makefile -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -k 0000000000000000 -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	openssl des-ecb -pbkdf2 -K 0123456789abcdef -in Makefile -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -k 0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	openssl des-ecb -pbkdf2 -K 0123456789abcdef -in /bin/ls -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -k 0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test decrypt too short/long key
	output_openssl=$(openssl des-ecb -pbkdf2 -K 000000000000ff -in /bin/ls -out $TEST_DIR/output $SUFFIX 2>&1)
	output_exec=$(./$exec des-ecb -d -k 000000000000ff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output_openssl" "$output_exec"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	output_openssl=$(openssl des-ecb -pbkdf2 -K 000000000000ffffff -in /bin/ls -out $TEST_DIR/output $SUFFIX 2>&1)
	output_exec=$(./$exec des-ecb -d -k 000000000000ffffff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output_openssl" "$output_exec"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	rm -rf $TEST_DIR
}

test_des-ecb_password() {
	mkdir -p $TEST_DIR
	# Test encrypt
	output=$(./$exec des-ecb -p abc -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -k abc -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(./$exec des-ecb -p Passwordpassw0rdPasswordPASSWORDPasswordpassword -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -k Passwordpassw0rdPasswordPASSWORDPasswordpassword -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test decrypt
	openssl des-ecb -pbkdf2 -k abc -in Makefile -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -p abc -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	openssl des-ecb -pbkdf2 -k Passwordpassw0rdPasswordPASSWORDPasswordpassword -in /bin/ls -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -p Passwordpassw0rdPasswordPASSWORDPasswordpassword -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	rm -rf $TEST_DIR
}

test_des-ecb_password_salt () {
	mkdir -p $TEST_DIR
	# Test encrypt salt
	output=$(./$exec des-ecb -p abc -s0000000000000000 -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -k abc -S 0000000000000000 -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(./$exec des-ecb -p passwd -s0123456789abcdef -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	openssl des-ecb -d -pbkdf2 -k passwd -S 0000000000000000 -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX # openssl ignore salt if specified in doc
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test encrypt too short/long salt
	output=$(./$exec des-ecb -p passwd -s0123456789abcdefff -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "hex string is too long, ignoring excess" "$output"
	openssl des-ecb -d -pbkdf2 -k passwd -S 0000000000000000ff -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX # openssl ignore salt if specified in doc ?
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(./$exec des-ecb -p passwd -s0123456789abcff -i/bin/ls -o$TEST_DIR/output 2>&1)
	assertEquals "hex string is too short, padding with zero bytes to length" "$output"
	openssl des-ecb -d -pbkdf2 -k passwd -S 000000000000ff -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX # openssl ignore salt if specified in doc ?
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test decrypt salt
	openssl des-ecb -pbkdf2 -k abc -S 0000000000000000 -in Makefile -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -p abc -s0000000000000000 -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	openssl des-ecb -pbkdf2 -k passwd -S 0123456789abcdef -in /bin/ls -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -p passwd -s0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	# Test decrypt too short/long salt
	openssl des-ecb -pbkdf2 -k passwd -S 0000000000000000ff -in /bin/ls -out $TEST_DIR/output $SUFFIX 2&> /dev/null
	output=$(./$exec des-ecb -d -p passwd -s0123456789abcdefff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1) # ignore salt
	assertEquals "" "$output"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	openssl des-ecb -pbkdf2 -k passwd -S 000000000000ff -in /bin/ls -out $TEST_DIR/output $SUFFIX 2&> /dev/null
	output=$(./$exec des-ecb -d -p passwd -s0123456789abcff -i$TEST_DIR/output -o$TEST_DIR/original 2>&1) # ignore salt
	assertEquals "" "$output"
	output=$(diff /bin/ls $TEST_DIR/original)
	assertEquals "" "$output"
	rm -rf $TEST_DIR
}

test_des-ecb_base64 () {
	mkdir -p $TEST_DIR
	# Decrypt base64
	openssl des-ecb -pbkdf2 -a -k passwd -S 0123456789abcdef -in README.md -out $TEST_DIR/output $SUFFIX
	output=$(./$exec des-ecb -d -a -p passwd -s0123456789abcdef -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff README.md $TEST_DIR/original)
	assertEquals "" "$output"
	# Decrypt without \n in file
	openssl des-ecb -pbkdf2 -a -k passwd -S 0123456789abcdef -in Makefile -out $TEST_DIR/output $SUFFIX
	cat $TEST_DIR/output | tr -d '\n' > $TEST_DIR/output2
	output=$(./$exec des-ecb -d -a -p passwd -s0123456789abcdef -i$TEST_DIR/output2 -o$TEST_DIR/original 2>&1)
	assertEquals "" "$output"
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	# Encrypt base64
	output=$(./$exec des-ecb -a -p passwd -s0123456789abcdef -iMakefile -o$TEST_DIR/output 2>&1)
	openssl des-ecb -d -pbkdf2 -a -k passwd -S 0123456789abcdef -in $TEST_DIR/output -out $TEST_DIR/original $SUFFIX
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	rm -rf $TEST_DIR
}

suite_addTest test_des-ecb_key
suite_addTest test_des-ecb_password
# suite_addTest test_des-ecb_password_salt # TODO: fix ubuntu 22.04
# suite_addTest test_des-ecb_base64 # TODO: fix ubuntu 22.04
