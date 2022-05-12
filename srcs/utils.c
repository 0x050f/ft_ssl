#include "ft_ssl.h"

size_t	ft_strlen(const char *s)
{
	const char *ptr;

	ptr = s;
	while (*ptr)
		++ptr;
	return (ptr - s);
}
