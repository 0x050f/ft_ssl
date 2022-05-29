#include "ft_ssl.h"

uint64_t		permutation(uint64_t block, uint8_t *table, size_t size)
{
	uint64_t	result = 0;

	for (size_t i = 0; i < size; i++)
		result += (1 << (size - table[i])) & block;
	return (result);
}

/* 32 bits half block and 48 bits subkey */
uint32_t		feistel_function(uint32_t half_block, uint64_t key)
{
	/* Expansion permutation */
	uint8_t E[48] = {32, 1, 2, 3, 4, 5,
					4, 5, 6, 7, 8, 9,
					8, 9, 10, 11, 12, 13,
					12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21,
					20, 21, 22, 23, 24, 25,
					24, 25, 26, 27, 28, 29,
					28, 29, 30, 31, 32, 1};
	/* P permutation */
	uint8_t P[32] = {16, 7, 20, 21, 29, 12, 28, 17,
					1, 15, 23, 26, 5, 18, 31, 10,
					2, 8, 24, 14, 32, 27, 3, 9,
					19, 13, 30, 6, 22, 11, 4, 25};

	/* TODO: [expansion permutation] */
	permutation(half_block, E, 48);
	uint64_t result = half_block ^ key; /* 48 bits xor */
	(void)result;
	/* TODO: substitution */
	/* TODO: [P permutation] */
	permutation(half_block, P, 32);
	return (0);
}

char			*des_ecb_encrypt(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	(void)str;
	(void)size;
	(void)res_len;
	(void)options;
	/* key and block are both 64 bits */
	uint64_t key;
	(void)key;

	/*
		initial permutation and final permutation:
		first bit of the output is taken from the 58th, second from 50th, ...
	*/
	uint8_t IP[64] = {58, 50, 42, 34, 26, 18, 10, 2,
					60, 52, 44, 36, 28, 20, 12, 4,
					62, 54, 46, 38, 30, 22, 14, 6,
					64, 56, 48, 40, 32, 24, 16, 8,
					57, 49, 41, 33, 25, 17, 9, 1,
					59, 51, 43, 35, 27, 19, 11, 3,
					61, 53, 45, 37, 29, 21, 13, 5,
					63, 55, 47, 39, 31, 23, 15, 7};
	uint8_t FP[64] = {40, 8, 48, 16, 56, 24, 64, 32,
					39, 7, 47, 15, 55, 23, 63, 31,
					38, 6, 46, 14, 54, 22, 62, 30,
					37, 5, 45, 13, 53, 21, 61, 29,
					36, 4, 44, 12, 52, 20, 60, 28,
					35, 3, 43, 11, 51, 19, 59, 27,
					34, 2, 42, 10, 50, 18, 58, 26,
					33, 1, 41, 9 , 49, 17, 57, 25};
	uint64_t block = 0;
	/* TODO: [init_permutation] */
	permutation(block, IP, 64);
	uint64_t to_xor = block;
	(void)to_xor;
	uint64_t to_feistel = block;
	(void)to_feistel;
	size_t nb_round = 16;
	for (size_t i = 0; i < nb_round; i++)
	{
		uint64_t tmp = to_feistel;
//		to_feistel = to_xor ^ feistel_function(to_feistel);
		to_xor = tmp;
	}
	/* TODO: [final_permutation] */
	permutation(block, FP, 64);
	return (0);
}

char			*des_ecb(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("des_ecb(\"%.*s\", %zu)\n", size, str, size);
	(void)res_len;
	(void)options;
	(void)str;
	(void)size;

	*res_len = 0;
	uint64_t ahah = 42;
	PRINT_BITS(ahah, 64);
	char *cipher = strdup("lol");
	return (cipher);
}
