#!/bin/bash

suite() {
	. ./tests/test_global.sh
	. ./tests/test_des-ecb.sh
}

. shunit2
