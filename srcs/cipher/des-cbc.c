#include "ft_ssl.h"
#include "cipher.h"

#define NB_ROUND 16

char			*des_cbc_encrypt_from_key_iv(
	uint8_t		*str,
	size_t		size,
	uint64_t	key,
	uint64_t	iv,
	size_t		*res_len
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
	uint64_t prev_block;
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

		/* CBC */
		if (!i)
			block ^= iv;
		else
			block ^= prev_block;

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
		prev_block = block;
	}
	free(plaintext);
	return (ciphertext);
}

// TODO: opti without key given parameter with Salted__ output size
// refacto a bit
char			*des_cbc_encrypt(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	char		*ciphertext;
	uint8_t		salt[8];
	uint64_t	iv;
	uint64_t	key;

	if (get_key_encrypt(&key, salt, options->key, options->salt, &iv, options->password, options->iter) < 0)
		return (NULL);
	if (options->iv)
	{
		uint64_t tmp = hex2int64(options->iv);
		if (strlen(options->iv) < 16)
		{
			dprintf(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n");
			tmp = tmp << ((16 - strlen(options->iv)) * 4);
		}
		else if (strlen(options->iv) > 16) // removing 8 bytes + auto with hex2int64 but print it
			dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
		memcpy(&iv, &tmp, 8);
	}
	else if (!options->password)
	{
		dprintf(STDERR_FILENO, "iv undefined\n");
		return (NULL);
	}
	ciphertext = des_cbc_encrypt_from_key_iv(str, size, key, iv, res_len);
	if (!ciphertext)
		return (NULL);
	if (!options->key)
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

char			*des_cbc_decrypt_from_key_iv(
	uint8_t		*str,
	size_t		size,
	uint64_t	key,
	uint64_t	iv,
	size_t		*res_len
) {
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
	uint64_t prev_block;
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

		/* CBC */
		if (!i)
			block ^= iv;
		else
			block ^= prev_block;

		b_memcpy(&prev_block, ciphertext + i, 8);
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

char			*des_cbc_decrypt(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	char		*plaintext;
	uint64_t	iv;
	uint64_t	key;

	if (get_key_decrypt(&str, &size, &key, options->key, &iv, options->password, options->iter) < 0)
		return (NULL);
	*res_len = 0;
	if (options->iv)
	{
		uint64_t tmp = hex2int64(options->iv);
		if (strlen(options->iv) < 16)
		{
			dprintf(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n");
			tmp = tmp << ((16 - strlen(options->iv)) * 4);
		}
		else if (strlen(options->iv) > 16) // removing 8 bytes + auto with hex2int64 but print it
			dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
		memcpy(&iv, &tmp, 8);
	}
	else if (!options->password)// ko
	{
		dprintf(STDERR_FILENO, "iv undefined\n");
		return (NULL);
	}
	plaintext = des_cbc_decrypt_from_key_iv(str, size, key, iv, res_len);
	return (plaintext);
}

char			*des_cbc(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("des_cbc(\"%.*s\", %zu)\n", (int)size, str, size);
	char *result = NULL;
	if (options->mode == CMODE_ENCODE)
	{
		result = des_cbc_encrypt(str, size, res_len, options);
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
		result = des_cbc_decrypt(str, size, res_len, options);
		if (options->base64)
			free(str);
	}
	return (result);
}
