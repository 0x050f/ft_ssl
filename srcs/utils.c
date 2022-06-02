#include "ft_ssl.h"

int			ceil(float num)
{
	int inum = (int)num;
	if (num == (float)inum)
		return (inum);
	return (inum + 1);
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
