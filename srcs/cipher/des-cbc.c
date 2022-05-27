#include "ft_ssl.h"

char			*des_cbc(unsigned char *str, size_t size, size_t *res_len, t_options *options)
{
	DPRINT("des_cbc(\"%.*s\", %zu)\n", size, str, size);
	(void)res_len;
	(void)options;
	char *cipher = strdup("lol");
	return (cipher);
}
