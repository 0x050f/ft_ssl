#include "ft_ssl.h"

char			*des_cbc(char *str, size_t size, size_t *res_len, t_options *options)
{
	(void)res_len;
	(void)options;
	printf("des_cbc(%s, %zu)\n", str, size);
	char *cipher = strdup("lol");
	return (cipher);
}
