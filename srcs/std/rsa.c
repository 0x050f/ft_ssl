#include "ft_ssl.h"
#include "std.h"

char	*rsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	DPRINT("rsa(\"%.*s\", %zu)\n", (int)size, query, size);
	(void)query;
	(void)size;
	(void)res_len;
	(void)options;
	return (NULL);
}
