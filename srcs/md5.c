#include "ft_ssl.h"
#include "md5.h"

char			*md5(char *str, size_t size)
{
	(void)str;
	(void)size;
	char *result = malloc(42);
	ft_memcpy(result, "salut", 6);
	return (result);
}
