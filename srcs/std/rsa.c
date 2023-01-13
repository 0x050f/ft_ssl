#include "ft_ssl.h"
#include "std.h"



char	*rsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	size_t		result_size;
	char		*result;

	DPRINT("rsa(\"%.*s\", %zu)\n", (int)size, query, size);

	result_size = 0;
	result = malloc(result_size);
	if (!result) {
		return (NULL);
	}
	if (!options->noout) {
		printf("writing RSA key\n");
		result_size += size;
		result = realloc(result, result_size);
		memcpy(result + result_size - size, query, size);
		if (!result) {
			return (NULL);
		}
	}
	*res_len = result_size;
	return (result);
}
