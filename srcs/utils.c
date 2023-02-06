#include "ft_ssl.h"

//TODO: make version with no str (mem)
char	*add_padding_str(char *str, size_t size_line, char *padd_str) {
	char		*new;
	size_t		new_len;
	size_t		i, j;

	new_len = strlen(str) + ((strlen(str) - 1) / size_line) * (strlen(padd_str) + 1) + 1;
	new = malloc(new_len);
	if (!new)
		return (NULL);
	i = 0;
	j = 0;
	while (i < strlen(str) + 1) {
		if (i && !(i % size_line)) {
			new[j++] = '\n';
			memcpy(new + j, padd_str, strlen(padd_str));
			j += strlen(padd_str);
		}
		new[j++] = str[i++];
	}
	return (new);
}

char		*bytes2hex(uint8_t *bytes, size_t size) {
	uint8_t	byte;
	char	*hex;

	hex = malloc(sizeof(char) * (size * 2 + 1));
	if (!hex) {
		return (NULL);
	}
	for (size_t i = 0; i < size; i++) {
		byte = bytes[i] & 0x0f;
		hex[i * 2] = (byte > 9) ? byte + 'a' : byte + '0';
		byte = (bytes[i] & 0xf0) >> 4;
		hex[i * 2 + 1] = (byte > 9) ? byte + 'a' : byte + '0';
	}
	hex[size * 2 - 1] = '\0';
	return (hex);
}

void		hex2bytes(uint8_t *result, size_t size, const char *hex)
{
	size_t		i = 0;
	while (i < size * 2 && ((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f') || (*hex >= 'A' && *hex <= 'F')))
	{
		char byte = *hex++;
		if (byte >= '0' && byte <= '9')
			byte = byte - '0';
		else if (byte >= 'a' && byte <='f')
			byte = byte - 'a' + 10;
		else if (byte >= 'A' && byte <='F')
			byte = byte - 'A' + 10;
		if (!(i % 2))
			result[i / 2] = byte & 0xf;
		else
			result[i / 2] = (result[i / 2] << 4) | (byte & 0xf);
		i++;
	}
}

uint64_t	hex2int64(const char *hex)
{
	size_t			i = 0;
	uint64_t		val = 0;
	while (((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f') || (*hex >= 'A' && *hex <= 'F')) && i < 16)
	{
		char byte = *hex++;
		if (byte >= '0' && byte <= '9')
			byte = byte - '0';
		else if (byte >= 'a' && byte <='f')
			byte = byte - 'a' + 10;
		else if (byte >= 'A' && byte <='F')
			byte = byte - 'A' + 10;
		val = (val << 4) | (byte & 0xf);
		i++;
	}
	return (val);
}

uint32_t	hex2int32(const char *hex)
{
	size_t			i = 0;
	uint32_t		val = 0;
	while (((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f') || (*hex >= 'A' && *hex <= 'F')) && i < 8)
	{
		char byte = *hex++;
		if (byte >= '0' && byte <= '9')
			byte = byte - '0';
		else if (byte >= 'a' && byte <='f')
			byte = byte - 'a' + 10;
		else if (byte >= 'A' && byte <='F')
			byte = byte - 'A' + 10;
		val = (val << 4) | (byte & 0xf);
		i++;
	}
	return (val);
}

/* backward memcpy */
void		*b_memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	i = 0;
	while (n && dest && src)
		((unsigned char *)dest)[i++] = ((unsigned char *)src)[--n];
	return (dest);
}

size_t		ft_strlen_special(char *str, size_t max)
{
	size_t i;

	i = 0;
	while (i < max && str[i] >= ' ' && str[i] <= '~')
		i++;
	return (i);
}

void		ft_toupper(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (str[i] >= 'a' && str[i] <= 'z')
			str[i] -= 'a' - 'A';
		i++;
	}
}

int			isint(char *str)
{
	size_t i;

	i = 0;
	if (!(str[i] == '-'))
		i++;
	while (str[i])
	{
		if (!(str[i] >= '0' && str[i] <= '9'))
			return (0);
		i++;
	}
	return (1);
}

int			ishexa(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (!((str[i] >= 'a' && str[i] <= 'f') || (str[i] >= 'A' && str[i] <= 'F') || (str[i] >= '0' && str[i] <= '9')))
			return (0);
		i++;
	}
	return (1);
}

int			isprintable(char *str)
{
	size_t i;

	i = 0;
	while (str[i])
	{
		if (str[i] < 32 || str[i] > 126)
			return (0);
		i++;
	}
	return (1);
}

char		*read_query(int fd, size_t *size)
{
	char	*query;
	char	*tmp;
	size_t	ret;
	char	buffer[4096];

	*size = 0;
	query = malloc(0);
	if (!query)
	{
		dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
		return (NULL);
	}
	while ((ret = read(fd, buffer, 4096)))
	{
		tmp = malloc(sizeof(char) * *size + ret);
		if (!tmp)
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			free(query);
			return (NULL);
		}
		if (query)
			memcpy(tmp, query, *size);
		memcpy(tmp + *size, buffer, ret);
		free(query);
		*size += ret;
		query = tmp;
	}
	return (query);
}

char	*first_nonchar(char *str, char c) {
	while (*str) {
		if (*str != c)
			return (str);
		str++;
	}
	return (str);
}
