#include "ft_ssl.h"

// https://en.wikipedia.org/wiki/MD5
char			*md5(uint8_t *str, size_t size)
{
	DPRINT("md5(\"%.*s\", %zu)\n", (int)size, str, size);
	int padding_zeroes;
	// setup msg
	//             v 0x80     v size
	// 64 bytes - 1 bytes - 8 bytes
	if (size % 64 > 55)
		padding_zeroes = 64 - ((size % 64) + 1) + 56;
	else
		padding_zeroes = 64 - ((size % 64) + 1) - 8;
	size_t	new_size = size + padding_zeroes + 1 + 8;
	unsigned char *msg = malloc(sizeof(char) * new_size);
	if (!msg)
		return (NULL);
	memcpy(msg, str, size);
	msg[size] = 0x80; // 0b10000000
	memset(msg + size + 1, 0, padding_zeroes);
	*(size_t *)(&msg[new_size - 8]) = size*8;

	// setup constant
	uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
	uint32_t K[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
				0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
				0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
				0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
				0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
				0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
				0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
				0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
				0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
				0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
				0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
				0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
				0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
				0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
				0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
				0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
	uint32_t a0 = 0x67452301;
	uint32_t b0 = 0xefcdab89;
	uint32_t c0 = 0x98badcfe;
	uint32_t d0 = 0x10325476;

	for (unsigned char *chunk = msg; (size_t)chunk - (size_t)msg < new_size; chunk += 64)
	{
		uint32_t *M = (void *)chunk;
		uint32_t A = a0;
		uint32_t B = b0;
		uint32_t C = c0;
		uint32_t D = d0;
		for (uint32_t i = 0; i < 64; i++)
		{
			uint32_t F, g;
			if (i < 16)
			{
				F = (B & C) | ((~B) & D);
				g = i;
			}
			else if (i < 32)
			{
				F = (D & B) | ((~D) & C);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48)
			{
				F = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			}
			else
			{
				F = C ^ (B | (~D));
				g = (7 * i) % 16;
			}
			F += A + K[i] + M[g];
			A = D;
			D = C;
			C = B;
			B += (F << s[i] | F >> (32 - s[i]));
		}
		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;
	}
	free(msg);
	char *hash = malloc(sizeof(char) * 33);
	if (!hash)
	{
		dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
		return (NULL);
	}
	for (int i = 0; i < 4; i++)
		snprintf(hash + i * 2, 32, "%02x", ((uint8_t *)&a0)[i]);
	for (int i = 0; i < 4; i++)
		snprintf(hash + 8 + i * 2, 32, "%02x", ((uint8_t *)&b0)[i]);
	for (int i = 0; i < 4; i++)
		snprintf(hash + 16 + i * 2, 32, "%02x", ((uint8_t *)&c0)[i]);
	for (int i = 0; i < 4; i++)
		snprintf(hash + 24 + i * 2, 32, "%02x", ((uint8_t *)&d0)[i]);
	hash[32] = '\0';
	return (hash);
}
