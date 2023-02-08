#include "ft_ssl.h"
#include "std.h"

/*
void	*rsa_encrypt() {
}

void	*rsa_decrypt() {
}
*/

char	*rsautl(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	DPRINT("rsautl(\"%.*s\", %zu)\n", (int)size, query, size);
	(void)query;
	(void)size;
	(void)res_len;
	struct rsa		rsa;
	uint8_t			*key;
	size_t			key_len;

	if (!options->inkey) {
		dprintf(STDERR_FILENO, "no private key given (-inkey parameter)\n");
		return (NULL);
	} else if (options->pubin && options->mode == CMODE_ENCRYPT) {
		dprintf(STDERR_FILENO, "A private key is needed for this operation\n");
		return (NULL);
	}
	else {
		int				fd;
		struct stat		buf;

		fd = open(options->inkey, O_RDONLY);
		if (fd < 0) {
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, "rsautl", options->inkey, strerror(errno));
			return (NULL);
		}
		if (fstat(fd, &buf) != 0) {
			close(fd);
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, "rsautl", options->inkey, strerror(errno));
			return (NULL);
		}
		if (S_ISDIR(buf.st_mode)) {
			close(fd);
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, "rsautl", options->inkey, "Is a directory");
			return (NULL);
		}
		key = read_query(fd, &key_len);
		if (!key)
			return (NULL);
		close(fd);
	}
	if (get_rsa_key(&rsa, key, key_len, options->pubin, NULL, NULL)) {
		dprintf(STDERR_FILENO, "Could not read private key from %s\n", options->inkey);
		return (NULL);
	}
	return (NULL);
}
