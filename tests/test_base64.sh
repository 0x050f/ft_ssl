#!/bin/bash

test_base64_simple()
{
	mkdir -p $TEST_DIR
	# Encrypt
	output=$(./$exec base64 -iMakefile -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	cat $TEST_DIR/output | base64 -d > $TEST_DIR/original
	output=$(diff Makefile $TEST_DIR/original)
	output=$(./$exec base64 -i/bin/cat -o$TEST_DIR/output 2>&1)
	assertEquals "" "$output"
	cat $TEST_DIR/output | base64 -d > $TEST_DIR/original
	output=$(diff /bin/cat $TEST_DIR/original)
	# Encrypt stdin
	output=$((./$exec base64 -o$TEST_DIR/output < Makefile) 2>&1)
	assertEquals "" "$output"
	cat $TEST_DIR/output | base64 -d > $TEST_DIR/original
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	# Encrypt stdout
	output=$(./$exec base64 -i Makefile | base64 -d > $TEST_DIR/original)
	assertEquals "" "$output"
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "" "$output"
	# Decrypt
	cat Makefile | base64 > $TEST_DIR/output
	output=$(./$exec base64 -d -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output" ""
	output=$(diff Makefile $TEST_DIR/original)
	assertEquals "$output" ""
	cat $exec | base64 > $TEST_DIR/output
	output=$(./$exec base64 -d -i$TEST_DIR/output -o$TEST_DIR/original 2>&1)
	assertEquals "$output" ""
	output=$(diff $exec $TEST_DIR/original)
	assertEquals "$output" ""
	rm -rf $TEST_DIR
}

suite_addTest test_base64_simple
