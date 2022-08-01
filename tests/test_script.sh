#!/bin/bash

exec=ft_ssl
TEST_DIR=/tmp/ftest_ssl

suite() {
	. ./tests/test_global.sh
	. ./tests/test_des-ecb.sh
	. ./tests/test_des-cbc.sh
}

. shunit2
