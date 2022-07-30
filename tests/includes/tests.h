#ifndef TESTS_H
# define TESTS_H

#include <check.h>
#include <stdlib.h>

#include "ft_ssl.h"
#include "cipher.h"

Suite *test_hmac_sha256(void);
Suite *test_pbkdf2_sha256(void);

#endif
