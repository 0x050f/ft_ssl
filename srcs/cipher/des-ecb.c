#include "ft_ssl.h"
#include "cipher.h"

#define NB_ROUND 16

uint64_t		permutation(uint64_t block, size_t size_input, uint8_t *table, size_t size_output)
{
	uint64_t	result = 0;

	for (uint64_t i = 0; i < size_output; i++)
	{
		uint64_t bit = (((uint64_t)1 << (size_input - table[i])) & block);
		if (bit)
			result |= ((uint64_t)1 << (size_output - (i + 1)));
	}
	return (result);
}

/* substitution function: OK ! */
uint32_t		substitution(uint64_t block)
{
	uint8_t S[8][64] = {{14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13},
						{15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9},
						{10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12},
						{7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14},
						{2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3},
						{12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13},
						{4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12},
						{13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11}};
	uint32_t	substitute;
	uint8_t		bytes[8];
	uint8_t		sub[4];

	memset(sub, 0, 4);
	memcpy(bytes, &block, 8);
	int j = 6;
	for (size_t i = 0; i < 8; i++)
	{
		uint8_t tmp;

		uint8_t left;
		if ((8 - ((i % 4) * 2)) != 8)
			left = ((uint8_t)(bytes[j] << (8 - ((i % 4) * 2))) >> 2);
		else
			left = 0;
		uint8_t right;
		if ((size_t)(j - 1) < 8 && (((i + 1) * 2) % 8))
			right = (uint8_t)(bytes[j - 1] >> (((i + 1) * 2) % 8));
		else
			right = 0;
		tmp = S[i][(left | right)];
		if ((i + 1) % 2)
			tmp = tmp << 4;
		sub[(7 - i) / 2] |= tmp;
		if ((i + 1) % 4)
			j--;
	}
	memcpy(&substitute, sub, 4);
	return (substitute);
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

	/* [expansion permutation] -> OK */
	uint64_t expanded = permutation(half_block, 32, E, 48);
	uint64_t result = expanded ^ key; /* 48 bits xor */
	/* Substitution (Each 6 bits converted to a 4 bits num) */
	half_block = substitution(result);
	/* [P permutation] -> OK */
	half_block = permutation(half_block, 32, P, 32);
	return (half_block);
}

void		get_salt(uint8_t dest[8], char *salt)
{
	uint64_t tmp = hex2int64(salt);
	if (strlen(salt) < 16)
	{
		dprintf(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n");
		tmp = tmp << ((16 - strlen(salt)) * 4);
	}
	else if (strlen(salt) > 16) // removing 8 bytes + auto with hex2int64 but print it
		dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
	b_memcpy(dest, &tmp, 8);
}

int			get_key_encrypt(
	uint64_t *key_output,
	uint8_t *salt_output,
	char *key,
	char *salt,
	uint64_t *iv,
	char *password,
	int iter
) {
	if (!key)
	{
		/* PKBFD */
		memset(salt_output, 0, 8);
		if (salt)
			get_salt(salt_output, salt);
		else
		{
			time_t	t;

			srand((unsigned) time(&t)); /* Initialize rand */
			/* Random salt */
			for (size_t i = 0; i < 8; i++)
				salt_output[i] = rand() % 256;
		}
		// default openssl -pbkdf2:  -iter 10000 -md sha256
		uint8_t *key_uint = pbkdf2(hmac_sha256, password, strlen(password), (char *)salt_output, 8, iter, 16);
		if (!key_uint)
			return (-1);
		b_memcpy(key_output, key_uint, 8);
		if (iv)
			b_memcpy(iv, key_uint + 8, 8);
		free(key_uint);
	}
	else
	{
		uint64_t tmp_key = hex2int64(key);
		/* if key was not provided with 8 bytes */
		if (strlen(key) < 16)
		{
			dprintf(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n");
			tmp_key = tmp_key << ((16 - strlen(key)) * 4);
		}
		else if (strlen(key) > 16) // removing 8 bytes + auto with hex2int64 but print it
			dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
		memcpy(key_output, &tmp_key, 8);
	}
	return (0);
}

char			*des_ecb_encrypt_from_key(
	uint8_t			*str,
	size_t			size,
	uint64_t		key,
	size_t			*res_len
) {
	size_t padding = 0;
	if (size % 8)
		padding = (8 - (size % 8));
	else
		padding = 8;
	*res_len = size + padding;
	unsigned char *plaintext = malloc(sizeof(char) * *res_len);
	if (!plaintext)
		return (NULL);
	char *ciphertext = malloc(sizeof(char) * *res_len);
	if (!ciphertext)
	{
		free(plaintext);
		return (NULL);
	}
	memcpy(plaintext, str, size);
	memset(plaintext + size, padding, padding);
	/* key and block are both 64 bits */
	for (size_t i = 0; i < *res_len; i += 8)
	{
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
		/* PC1 Left/Right */
		uint8_t PC1[2][28] = {{57, 49, 41, 33, 25, 17, 9,
						1, 58, 50, 42, 34, 26, 18,
						10, 2, 59, 51, 43, 35, 27,
						19, 11, 3, 60, 52, 44, 36},
						{63, 55, 47, 39, 31, 23, 15,
						7, 62, 54, 46, 38, 30, 22,
						14, 6, 61, 53, 45, 37, 29,
						21, 13, 5, 28, 20, 12, 4}};
		uint8_t PC2[48] = {14, 17, 11, 24, 1, 5,
						3, 28, 15, 6, 21, 10,
						23, 19, 12, 4, 26, 8,
						16, 7, 27, 20, 13, 2,
						41, 52, 31, 37, 47, 55,
						30, 40, 51, 45, 33, 48,
						44, 49, 39, 56, 34, 53,
						46, 42, 50, 36, 29, 32};

		uint64_t block;
		b_memcpy(&block, plaintext + i, 8);

		/* [init_permutation] -> OK */
		block = permutation(block, 64, IP, 64);
		uint32_t to_xor = (block >> 32);
		uint32_t to_feistel = block;
		uint64_t subkeys[NB_ROUND];
		uint32_t subkey_left = permutation(key, 64, PC1[0], 28);
		uint32_t subkey_right = permutation(key, 64, PC1[1], 28);
		uint8_t round_rotations_subkey[NB_ROUND] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
		for (size_t j = 0; j < NB_ROUND; j++)
		{
			subkey_left = ((subkey_left << round_rotations_subkey[j]) | (subkey_left >> (28 - round_rotations_subkey[j])));
			subkey_left &= 0b0001111111111111111111111111111; /* keep in on 28 bits */
			subkey_right = ((subkey_right << round_rotations_subkey[j]) | (subkey_right >> (28 - round_rotations_subkey[j])));
			subkey_right &= 0b0001111111111111111111111111111; /* keep in on 28 bits */
			subkeys[j] = ((uint64_t)subkey_left << 28) | subkey_right;
			subkeys[j] = permutation(subkeys[j], 56, PC2, 48);
		}
		for (size_t j = 0; j < NB_ROUND; j++)
		{
			uint32_t tmp = to_feistel;
			to_feistel = to_xor ^ feistel_function(to_feistel, subkeys[j]);
			to_xor = tmp;
		}
		block = ((uint64_t)to_feistel << 32) | to_xor;
		/* [final_permutation] -> OK*/
		block = permutation(block, 64, FP, 64);
		DPRINT("res block: %llx\n",block);
		b_memcpy(ciphertext + i, &block, 8);
	}
	free(plaintext);
	return (ciphertext);
}

// TODO: opti without key given parameter with Salted__ output size
// refacto a bit
char			*des_ecb_encrypt(
	unsigned char	*str,
	size_t			size,
	char			*key_input,
	char			*salt_input,
	char			*password,
	int				iter,
	size_t			*res_len
) {
	char		*ciphertext;
	uint8_t		salt[8];
	uint64_t	key;

	if (get_key_encrypt(&key, salt, key_input, salt_input, NULL, password, iter) < 0)
		return (NULL);
	ciphertext = des_ecb_encrypt_from_key(str, size, key, res_len);
	if (!ciphertext)
		return (NULL);
	if (!key_input)
	{
		*res_len += 16;
		char *new_cipher = malloc(sizeof(char) * *res_len);
		if (!new_cipher)
		{
			free(ciphertext);
			return (NULL);
		}
		memcpy(new_cipher, "Salted__", 8);
		memcpy(new_cipher + 8, salt, 8);
		memcpy(new_cipher + 16, ciphertext, *res_len - 16);
		free(ciphertext);
		ciphertext = new_cipher;
	}
	return (ciphertext);
}

int		get_key_decrypt(
	unsigned char **str,
	size_t *size,
	uint64_t *key_output,
	char *key,
	uint8_t *salt,
	uint64_t *iv,
	char *password,
	int iter
) {
	uint8_t		new_salt[8];

	if (!key)
	{
		/* PKBDF */
		if (!salt) {
			memset(new_salt, 0, 8);
			/* ignore salt on decrypt */
			/* Get salt */
			if (*size < 16 || memcmp(*str, "Salted__", 8))
			{
				dprintf(STDERR_FILENO, "bad magic number\n");
				return (-1);
			}
			memcpy(new_salt, *str + 8, 8);
			*str += 16;
			*size -= 16;
			salt = new_salt;
		}
		// default openssl -pbkdf2:  -iter 10000 -md sha256
		uint8_t *key_uint = pbkdf2(hmac_sha256, password, strlen(password), (char *)salt, 8, iter, 16);
		if (!key_uint)
			return (-1);
		b_memcpy(key_output, key_uint, 8);
		if (iv)
			b_memcpy(iv, key_uint + 8, 8);
		free(key_uint);
	}
	else
	{
		uint64_t tmp_key = hex2int64(key);
		/* if key was not provided with 8 bytes */
		if (strlen(key) < 16)
		{
			dprintf(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n");
			tmp_key = tmp_key << ((16 - strlen(key)) * 4);
		}
		else if (strlen(key) > 16) // removing 8 bytes + auto with hex2int64 but print it
			dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
		memcpy(key_output, &tmp_key, 8);
	}
	return (0);
}

char			*des_ecb_decrypt_from_key(
	uint8_t		*str,
	size_t		size,
	uint64_t	key,
	size_t		*res_len
) {
	*res_len = 0;
	unsigned char *ciphertext = malloc(sizeof(char) * size);
	if (!ciphertext)
		return (NULL);
	char *plaintext = malloc(sizeof(char) * size);
	if (!plaintext)
	{
		free(ciphertext);
		return (NULL);
	}
	memcpy(ciphertext, str, size);
	/* key and block are both 64 bits */
	for (size_t i = 0; i < size - 7; i += 8)
	{
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
		/* PC1 Left/Right */
		uint8_t PC1[2][28] = {{57, 49, 41, 33, 25, 17, 9,
						1, 58, 50, 42, 34, 26, 18,
						10, 2, 59, 51, 43, 35, 27,
						19, 11, 3, 60, 52, 44, 36},
						{63, 55, 47, 39, 31, 23, 15,
						7, 62, 54, 46, 38, 30, 22,
						14, 6, 61, 53, 45, 37, 29,
						21, 13, 5, 28, 20, 12, 4}};
		uint8_t PC2[48] = {14, 17, 11, 24, 1, 5,
						3, 28, 15, 6, 21, 10,
						23, 19, 12, 4, 26, 8,
						16, 7, 27, 20, 13, 2,
						41, 52, 31, 37, 47, 55,
						30, 40, 51, 45, 33, 48,
						44, 49, 39, 56, 34, 53,
						46, 42, 50, 36, 29, 32};

		uint64_t block;
		b_memcpy(&block, ciphertext + i, 8);

		/* [init_permutation] -> OK */
		block = permutation(block, 64, IP, 64);
		uint32_t to_xor = (block >> 32);
		uint32_t to_feistel = block;
		uint64_t subkeys[NB_ROUND];
		uint32_t subkey_left = permutation(key, 64, PC1[0], 28);
		uint32_t subkey_right = permutation(key, 64, PC1[1], 28);
		uint8_t round_rotations_subkey[NB_ROUND] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
		for (size_t j = 0; j < NB_ROUND; j++)
		{
			subkey_left = ((subkey_left << round_rotations_subkey[j]) | (subkey_left >> (28 - round_rotations_subkey[j])));
			subkey_left &= 0b0001111111111111111111111111111; /* keep in on 28 bits */
			subkey_right = ((subkey_right << round_rotations_subkey[j]) | (subkey_right >> (28 - round_rotations_subkey[j])));
			subkey_right &= 0b0001111111111111111111111111111; /* keep in on 28 bits */
			subkeys[j] = ((uint64_t)subkey_left << 28) | subkey_right;
			subkeys[j] = permutation(subkeys[j], 56, PC2, 48);
		}
		for (size_t j = 0; j < NB_ROUND; j++)
		{
			uint32_t tmp = to_feistel;
			to_feistel = to_xor ^ feistel_function(to_feistel, subkeys[NB_ROUND - j - 1]);
			to_xor = tmp;
		}
		block = ((uint64_t)to_feistel << 32) | to_xor;
		/* [final_permutation] -> OK*/
		block = permutation(block, 64, FP, 64);
		DPRINT("res block: %llx\n",block);
		b_memcpy(plaintext + i, &block, 8);
		if (i <= size - 8)
			*res_len = size - (plaintext + i)[7];
	}
	if (size % 8)
		dprintf(STDERR_FILENO, "bad decrypt\n");
	free(ciphertext);
	return (plaintext);
}

char			*des_ecb_decrypt(
	unsigned char *str,
	size_t size,
	char *key_input,
	char *password,
	int iter,
	size_t *res_len
) {
	char		*plaintext;
	uint64_t	key;

	if (get_key_decrypt(&str, &size, &key, key_input, NULL, NULL, password, iter) < 0)
		return (NULL);
	plaintext = des_ecb_decrypt_from_key(str, size, key, res_len);
	return (plaintext);
}

char			*des_ecb(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("des_ecb(\"%.*s\", %zu)\n", (int)size, str, size);
	if (options->iv)
		dprintf(STDERR_FILENO, "warning: iv not used by this cipher\n");
	char *result = NULL;
	if (options->mode == CMODE_ENCODE)
	{
		result = des_ecb_encrypt(str, size, options->key, options->salt, options->password, options->iter, res_len);
			if (options->base64)
			{
				char *new_result = base64_encode((unsigned char *)result, *res_len, res_len);
				free(result);
				if (!new_result)
					return (NULL);
				result = new_result;
			}
	}
	else if (options->mode == CMODE_DECODE)
	{
		if (options->base64)
		{
			str = (unsigned char *)base64_decode(str, size, &size);
			if (!str)
			{
				dprintf(STDERR_FILENO, "error reading input file\n");
				return (NULL);
			}
		}
		result = des_ecb_decrypt(str, size, options->key, options->password, options->iter, res_len);
	}
	return (result);
}
