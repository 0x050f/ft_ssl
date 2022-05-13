#include "ft_ssl.h"

size_t		ft_strlen(const char *s)
{
	const char *ptr;

	ptr = s;
	while (*ptr)
		++ptr;
	return (ptr - s);
}

int			ft_strcmp(const char *s1, const char *s2)
{
	int i;

	i = 0;
	while (s1[i] && s2[i] && s1[i] == s2[i])
		i++;
	return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

size_t	ft_strcpy(char *dst, const char *src)
{
	size_t		i;

	i = 0;
	while (src[i] != '\0')
	{
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
	return (i);
}

void		*ft_memset(void *b, int c, size_t len)
{
	unsigned char	*pt;

	pt = (unsigned char *)b;
	while (len--)
		*pt++ = (unsigned char)c;
	return (b);
}

void		*ft_memcpy(void *dst, const void *src, size_t n)
{
	char	*pt_src;
	char	*pt_dst;

	pt_src = (char *)src;
	pt_dst = (char *)dst;
	while (n--)
		*pt_dst++ = *pt_src++;
	return (dst);
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
