#include "ft_ssl.h"
#include "cipher.h"

char			*base64_decode(unsigned char *str, size_t size, size_t *res_len)
{
	char base[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/* remove all '\n' */
	for (size_t i = 0; i < size; i++)
	{
		if (str[i] == '\n')
		{
			memmove(&str[i], &str[i + 1], (size - i - 1));
			size--;
		}
	}
	size_t padding = 0;
	for (size_t i = 0; i < size; i++)
	{
		if (!memchr(base, str[i], 64) && str[i] != '=') /* not a base64 char */
			return (NULL);
		if (str[i] == '=')
		{
			padding++;
			if (i + 1 < size && str[i + 1] != '=')
			{
				size = size - (size - (i + 1)); // ignore char after '='
				break ;
			}
		}
	}
	if (padding > 2)
		return (NULL);
	*res_len = (size * 6 / 8) - padding;
	char *cipher = malloc(sizeof(char) * *res_len);
	if (!cipher)
		return (NULL);
	size_t j = 0;
	for (size_t i = 0; i < *res_len; i++)
	{
		uint8_t index1 = (void *)memchr(base, str[j], 64) - (void *)base;
		uint8_t index2 = (void *)memchr(base, str[j + 1], 64) - (void *)base;
		uint8_t c = (index1 << (2 * ((i % 3) + 1))) | (index2 >> (4 - ((i % 3) * 2)));
		cipher[i] = c;
		if (!((i + 1) % 3))
			j++;
		j++;
	}
	return (cipher);
}

char			*base64_encode(unsigned char *str, size_t size, size_t *res_len)
{
	char base[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	*res_len = (ceil((size * 8.0 / 6.0) / 4.0)) * 4;
	char *cipher = malloc(sizeof(char) * *res_len);
	if (!cipher)
		return (NULL);
	size_t padding = 0;
	if ((size * 8) % 6)
		padding = (6 - ((size * 8) % 6)) / 2;
	long j = -1;
	for (size_t i = 0; i < *res_len - padding; i++)
	{
		uint8_t left;
		if ((8 - ((i % 4) * 2)) != 8)
			left = ((uint8_t)(str[j] << (8 - ((i % 4) * 2))) >> 2);
		else
			left = 0;
		uint8_t right;
		if ((size_t)(j + 1) < size && (((i + 1) * 2) % 8))
			right = str[j + 1] >> (((i + 1) * 2) % 8);
		else
			right = 0;
		size_t index = left | right;
		cipher[i] = base[index];
		if ((i + 1) % 4 || !i)
			j++;
	}
	for (size_t i = 0; i < padding; i++)
		cipher[*res_len - (padding - i)] = '=';
	return (cipher);
}

char			*base64(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("base64(\"%.*s\", %zu)\n", (int)size, str, size);
	char *cipher;
	if (options->mode == CMODE_ENCODE)
		cipher = base64_encode(str, size, res_len);
	else
		cipher = base64_decode(str, size, res_len);
	return (cipher);
}
