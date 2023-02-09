#include "ft_ssl.h"
#include "std.h"

char	*to_printable(void *bytes, size_t size) {
	char *result;

	result = malloc(size + 1);
	if (!result)
		return (NULL);
	for (size_t i = 0; i < size; i++) {
		unsigned char byte = ((unsigned char *)bytes)[i];
		if (byte >= 32 && byte <= 126)
			result[i] = byte;
		else
			result[i] = '.';
	}
	result[size] = '\0';
	return (result);
}

char	*hexdump(void *to_hex, size_t size) {
	size_t	i;
	char	*result;

	result = malloc(1);
	if (!result)
		return (NULL);
	result[0] = '\0';
	for (i = 0; i < size; i++) {
		if (!(i % 16)) {
			int n = i / 16;
			char *head = bytes2hex((uint8_t *)&n, 2);
			if (!head) {
				free(result);
				return (NULL);
			}
			result = realloc(result, strlen(result) + strlen(head) + 3 + 1);
			if (!result) {
				free(head);
				return (NULL);
			}
			strcpy(result + strlen(result), head);
			free(head);
			strcpy(result + strlen(result), " - ");
		}
		char *hex = bytes2hex(&((uint8_t *)to_hex)[i], 1);
		if (!hex) {
			free(result);
			return (NULL);
		}
		result = realloc(result, strlen(result) + strlen(hex) + 1 + 1);
		if (!result) {
			free(hex);
			return (NULL);
		}
		strcpy(result + strlen(result), hex);
		free(hex);
		if ((i % 16) == 7)
			strcpy(result + strlen(result), "-");
		else
			strcpy(result + strlen(result), " ");
		if ((i % 16) == 15) {
			char *printable = to_printable(&((uint8_t *)to_hex)[i - (i % 16)], 16 - i % 16);
			if (!printable) {
				free(result);
				return (NULL);
			}
			int spaces_to_add = 3 * ((i + 1) % 16) + 2;
			result = realloc(result, strlen(result) + spaces_to_add + strlen(printable) + 1 + 1);
			if (!result) {
				free(printable);
				return (NULL);
			}
			result[strlen(result) + spaces_to_add] = '\0';
			memset(result + strlen(result), ' ', spaces_to_add);
			strcpy(result + strlen(result), printable);
			free(printable);
			strcpy(result + strlen(result), "\n");
		}
	}
	if ((i % 16) != 0) {
		char *printable = to_printable(&((uint8_t *)to_hex)[i - (i % 16)], 16 - i % 16);
		if (!printable) {
			free(result);
			return (NULL);
		}
		int spaces_to_add = 3 * (i % 16) + 2;
		result = realloc(result, strlen(result) + spaces_to_add + strlen(printable) + 1 + 1);
		if (!result) {
			free(printable);
			return (NULL);
		}
		result[strlen(result) + spaces_to_add] = '\0';
		memset(result + strlen(result), ' ', spaces_to_add);
		strcpy(result + strlen(result), printable);
		free(printable);
		strcpy(result + strlen(result), "\n");
	}
	return (result);
}

/* RSAEP - RSA Encryption Primitive - Encrypts a message using a public key */
int		rsaep(unsigned __int128 *c, unsigned __int128 n, unsigned __int128 e, unsigned __int128 m) {
	if (m >= n) {
		dprintf(STDERR_FILENO, "message representative out of range\n");
		return (1);
	}
	*c = power_mod(m, e, n);
	return (0);
}

/* RSADP - RSA Decryption Primitive - Decrypts ciphertext using a private key */
int		rsadp(unsigned __int128 *m, unsigned __int128 n, unsigned __int128 d, unsigned __int128 c) {
	if (c >= n) {
		dprintf(STDERR_FILENO, "ciphertext representative out of range\n");
		return (1);
	}
	*m = power_mod(c, d, n);
	return (0);
}

char	*rsautl(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	DPRINT("rsautl(\"%.*s\", %zu)\n", (int)size, query, size);
	(void)query;
	(void)size;
	(void)res_len;
	char			*result;
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
		free(key);
		dprintf(STDERR_FILENO, "Could not read private key from %s\n", options->inkey);
		return (NULL);
	}
	free(key);
	if (get_size_in_bits(rsa.n) > 64) {
		dprintf(STDERR_FILENO, "Can't compute > 64bits key\n");
		return (NULL);
	}
	if ((int)size * 8 > get_size_in_bits(rsa.n)) {
		dprintf(STDERR_FILENO, "data greater than mod len\n");
		return (NULL);
	}
	unsigned __int128 m;
	unsigned __int128 c;
	size_t nb_bytes = get_size_in_bits(rsa.n) / 8;
	if (nb_bytes % 8)
		nb_bytes += 8 - (nb_bytes % 8); // round up to 8 bytes

	result = malloc(nb_bytes);
	if (!result)
		return (NULL);

	m = 0;
	c = 0;
	if (options->mode == CMODE_ENCRYPT) {
		b_memcpy(&m, query, size);
		if (rsaep(&c, rsa.n, rsa.e, m))
			return (NULL);
		b_memcpy(result, &c, nb_bytes);
	} else {
		b_memcpy(&c, query, size);
		if (rsadp(&m, rsa.n, rsa.d, c))
			return (NULL);
		b_memcpy(result, &m, nb_bytes);
	}
	*res_len = nb_bytes;
	if (options->hexdump) {
		char *res = hexdump(result, nb_bytes);
		free(result);
		if (!res)
			return (NULL);
		*res_len = strlen(res);
		return (res);
	}
	return (result);
}
