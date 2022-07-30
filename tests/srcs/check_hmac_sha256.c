#include "tests.h"

/*
	RFC 4231
	https://datatracker.ietf.org/doc/html/rfc4231
*/

void	test_vector(char *data, int data_len, char *key, int key_len, char *expected_output)
{
	char *digest = hmac_sha256((uint8_t *)data, data_len, (uint8_t *)key, key_len);
	ck_assert_mem_eq(digest, expected_output, sizeof(expected_output));
	free(digest);
}

START_TEST (hmac_sha256_test_vectors_1)
{
	int key_len = 20;
	char key[key_len];
	char data[] = "Hi There";
	int data_len = strlen(data);
	char expected_output[64] = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

	memset(key, 0x0b, key_len);
	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_2)
{
	char key[] = "Jefe";
	int key_len = strlen(key);
	char data[] = "what do ya want for nothing?";
	int data_len = strlen(data);
	char expected_output[64] = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_3)
{
	int key_len = 20;
	char key[key_len];
	int data_len = 50;
	char data[data_len];

	memset(key, 0xaa, key_len);
	memset(data, 0xdd, data_len);
	char expected_output[64] = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_4)
{
	int key_len = 25;
	char key[key_len];
	int data_len = 50;
	char data[data_len];

	for (size_t i = 0; i < (size_t)key_len; i++)
		key[i] = i + 1;
	memset(data, 0xcd, data_len);
	char expected_output[64] = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_5)
{
	int key_len = 20;
	char key[key_len];
	char data[] = "Test With Truncation";
	int data_len = strlen(data);

	memset(key, 0x0c, key_len);
	char expected_output[32] = "a3b6167473100ee06e0c796c2955552b";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_6)
{
	int key_len = 131;
	char key[key_len];
	char data[] = "Test Using Larger Than Block-Size Key - Hash Key First";
	int data_len = strlen(data);

	memset(key, 0xaa, key_len);
	char expected_output[64] = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

START_TEST (hmac_sha256_test_vectors_7)
{
	int key_len = 131;
	char key[key_len];
	char data[] = "This is a test using a larger than block-size key and a larger\
 than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
	int data_len = strlen(data);

	memset(key, 0xaa, key_len);
	char expected_output[64] = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

	test_vector(data, data_len, key, key_len, expected_output);
}
END_TEST

Suite *test_hmac_sha256(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("hmac_sha256");
	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, hmac_sha256_test_vectors_1);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_2);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_3);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_4);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_5);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_6);
	tcase_add_test(tc_core, hmac_sha256_test_vectors_7);
	suite_add_tcase(s, tc_core);

	return s;
}
