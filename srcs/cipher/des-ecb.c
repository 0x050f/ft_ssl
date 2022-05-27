#include "ft_ssl.h"

char			*des_ecb(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("des_ecb(\"%.*s\", %zu)\n", size, str, size);
	(void)res_len;
	(void)options;
	(void)str;
	(void)size;
	char *cipher = strdup("lol");
	return (cipher);
}
