#include "tests.h"

void	test_vector_pbkdf2(char *password, int password_len, char *salt, int salt_len, int c, int dklen, char *expected_output)
{
	uint8_t *digest = pbkdf2(hmac_sha256, password, password_len, salt, salt_len, c, dklen);
	ck_assert_mem_eq(digest, expected_output, dklen);
	free(digest);
}

START_TEST (hmac_sha256_test_vectors_1)
{
	char password[] = "password";
	int password_len = strlen(password);
	char salt[] = "salt";
	int salt_len = strlen(salt);
	int c = 1;
	int dklen = 20;
	char expected_output[] = "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37\xa8\x65\x48\xc9";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_2)
{
	char password[] = "password";
	int password_len = strlen(password);
	char salt[] = "salt";
	int salt_len = strlen(salt);
	int c = 2;
	int dklen = 20;
	char expected_output[] = "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0\x2a\x30\x3f\x8e";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_3)
{
	char password[] = "password";
	int password_len = strlen(password);
	char salt[] = "salt";
	int salt_len = strlen(salt);
	int c = 4096;
	int dklen = 20;
	char expected_output[] = "\xc5\xe4\x78\xd5\x92\x88\xc8\x41\xaa\x53\x0d\xb6\x84\x5c\x4c\x8d\x96\x28\x93\xa0";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

/*
START_TEST (hmac_sha256_test_vectors_4)
{
	char password[] = "password";
	int password_len = strlen(password);
	char salt[] = "salt";
	int salt_len = strlen(salt);
	int c = 16777216;
	int dklen = 20;
	char expected_output[] = "\xcf\x81\xc6\x6f\xe8\xcf\xc0\x4d\x1f\x31\xec\xb6\x5d\xab\x40\x89\xf7\xf1\x79\xe8";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST
*/

START_TEST (hmac_sha256_test_vectors_5)
{
	char password[] = "passwordPASSWORDpassword";
	int password_len = strlen(password);
	char salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	int salt_len = strlen(salt);
	int c = 4096;
	int dklen = 25;
	char expected_output[] = "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_6)
{
	char password[] = "pass\0word";
	int password_len = 9;
	char salt[] = "sa\0lt";
	int salt_len = 5;
	int c = 4096;
	int dklen = 16;
	char expected_output[] = "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3c\x69\x62\x26\x65\x0a\x86\x87";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_7)
{
	char password[] = "passwd";
	int password_len = strlen(password);
	char salt[] = "salt";
	int salt_len = strlen(salt);
	int c = 1;
	int dklen = 128;
	char expected_output[] = "\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16\x64\xb3\x9d\x77\xef\x31\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83\xc2\x94\xe8\x50\x15\x03\x90\xe1\x16\x0c\x34\xd6\x2e\x96\x65\xd6\x59\xae\x49\xd3\x14\x51\x0f\xc9\x82\x74\xcc\x79\x68\x19\x68\x10\x4b\x8f\x89\x23\x7e\x69\xb2\xd5\x49\x11\x18\x68\x65\x8b\xe6\x2f\x59\xbd\x71\x5c\xac\x44\xa1\x14\x7e\xd5\x31\x7c\x9b\xae\x6b\x2a";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_8)
{
	char password[] = "Password";
	int password_len = strlen(password);
	char salt[] = "NaCl";
	int salt_len = strlen(salt);
	int c = 80000;
	int dklen = 128;
	char expected_output[] = "\x4d\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27\x01\xf9\x64\x1a\x44\x18\xd0\x4c\x04\x14\xae\xff\x08\x87\x6b\x34\xab\x56\xa1\xd4\x25\xa1\x22\x58\x33\x54\x9a\xdb\x84\x1b\x51\xc9\xb3\x17\x6a\x27\x2b\xde\xbb\xa1\xd0\x78\x47\x8f\x62\xb3\x97\xf3\x3c\x8d\x62\xaa\xe8\x5a\x11\xcd\xde\x82\x9d\x89\xcb\x6f\xfd\x1a\xb0\xe6\x3a\x98\x1f\x87\x47\xd2\xf2\xf9\xfe\x58\x74\x16\x5c\x83\xc1\x68\xd2\xee\xd1\xd2\xd5\xca\x40\x52\xde\xc2\xbe\x57\x15\x62\x3d\xa0\x19\xb8\xc0\xec\x87\xdc\x36\xaa\x75\x1c\x38\xf9\x89\x3d\x15\xc3";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_9)
{
	char password[] = "Password";
	int password_len = strlen(password);
	char salt[] = "sa\0lt";
	int salt_len = 5;
	int c = 4096;
	int dklen = 256;
	char expected_output[] = "\x43\x6c\x82\xc6\xaf\x90\x10\xbb\x0f\xdb\x27\x47\x91\x93\x4a\xc7\xde\xe2\x17\x45\xdd\x11\xfb\x57\xbb\x90\x11\x2a\xb1\x87\xc4\x95\xad\x82\xdf\x77\x6a\xd7\xce\xfb\x60\x6f\x34\xfe\xdc\xa5\x9b\xaa\x59\x22\xa5\x7f\x3e\x91\xbc\x0e\x11\x96\x0d\xa7\xec\x87\xed\x04\x71\xb4\x56\xa0\x80\x8b\x60\xdf\xf7\x57\xb7\xd3\x13\xd4\x06\x8b\xf8\xd3\x37\xa9\x9c\xae\xde\x24\xf3\x24\x8f\x87\xd1\xbf\x16\x89\x2b\x70\xb0\x76\xa0\x7d\xd1\x63\xa8\xa0\x9d\xb7\x88\xae\x34\x30\x0f\xf2\xf2\xd0\xa9\x2c\x9e\x67\x81\x86\x18\x36\x22\xa6\x36\xf4\xcb\xce\x15\x68\x0d\xfe\xa4\x6f\x6d\x22\x4e\x51\xc2\x99\xd4\x94\x6a\xa2\x47\x11\x33\xa6\x49\x28\x8e\xef\x3e\x42\x27\xb6\x09\xcf\x20\x3d\xba\x65\xe9\xfa\x69\xe6\x3d\x35\xb6\xff\x43\x5f\xf5\x16\x64\xcb\xd6\x77\x3d\x72\xeb\xc3\x41\xd2\x39\xf0\x08\x4b\x00\x43\x88\xd6\xaf\xa5\x04\xee\xe6\x71\x9a\x7a\xe1\xbb\x9d\xaf\x6b\x76\x28\xd8\x51\xfa\xb3\x35\xf1\xd1\x39\x48\xe8\xee\x6f\x7a\xb0\x33\xa3\x2d\xf4\x47\xf8\xd0\x95\x08\x09\xa7\x00\x66\x60\x5d\x69\x60\x84\x7e\xd4\x36\xfa\x52\xcd\xfb\xcf\x26\x1b\x44\xd2\xa8\x70\x61";

	test_vector_pbkdf2(password, password_len, salt, salt_len, c, dklen, expected_output);
}
END_TEST

Suite *test_pbkdf2_sha256(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("hmac_pbkdf2_sha256");
	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, hmac_sha256_test_vectors_1);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_2);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_3);
//	tcase_add_test(tc_core, hmac_sha256_test_vectors_4); -> timeout
	tcase_add_test(tc_core, hmac_sha256_test_vectors_5);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_6);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_7);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_8);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_9);
	suite_add_tcase(s, tc_core);

	return s;
}
