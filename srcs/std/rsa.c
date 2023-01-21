#include "ft_ssl.h"
#include "std.h"

char	*get_hexa_repr(unsigned __int128 n) {
	char				buf[3];
	char				*hexa;
	size_t				size_nb;
	size_t				tmp;
	unsigned __int128	nbis;

	nbis = n;
	size_nb = 0;
	while (nbis) {
		nbis /= 256;
		size_nb++;
	}

	nbis = n;
	hexa = malloc((size_nb * 3) * sizeof(char));
	if (!hexa)
		return (NULL);
	tmp = size_nb;
	while (tmp--) {
		sprintf(buf, "%02x:", ((uint8_t *)&nbis)[0]);
		memcpy(&hexa[tmp * 3], buf, 3);
		nbis /= 256;
	}
	hexa[size_nb * 3 - 1] = '\0';
	return (hexa);
}

int		get_size_in_bits(unsigned __int128 n) {
	unsigned __int128 i;

	for (i = 0; i < 128 && n; i++) {
		if (((unsigned __int128)1 << i) & n) {
			n ^= ((unsigned __int128)1 << i);
		}
	}
	return (i);
}

char	*add_padding_str(char *str, size_t size_line, char *padd_str) {
	char		*new;
	size_t		new_len;
	size_t		i, j;

	new_len = strlen(str) + ((strlen(str) - 1) / size_line) * (strlen(padd_str) + 1) + 1;
	new = malloc(new_len);
	if (!new)
		return (NULL);
	i = 0;
	j = 0;
	while (i < strlen(str) + 1) {
		if (i && !(i % size_line)) {
			new[j++] = '\n';
			memcpy(new + j, padd_str, strlen(padd_str));
			j += strlen(padd_str);
		}
		new[j++] = str[i++];
	}
	return (new);
}

static char *var_name[] = {
	[0]		= "modulus",
	[1]		= "publicExponent",
	[2]		= "privateExponent",
	[3]		= "prime1",
	[4]		= "prime2",
	[5]		= "exponent1",
	[6]		= "exponent2",
	[7]		= "coefficient"
};

char	*get_text_from_rsa(struct rsa *rsa) {
		unsigned __int128 		buff[sizeof(struct rsa)];
		int						ret;
		char					*tmp;
		char					*str;

		memcpy(buff, rsa, sizeof(struct rsa));
		str = strdup("");
		if (!str)
			return (NULL);
		ret = asprintf(&tmp, "Private-Key: (%d bit, %d primes)\n", get_size_in_bits(rsa->n), 2);
		if (ret < 0) {
			free(str);
			return (NULL);
		}
		str = realloc(str, strlen(str) + strlen(tmp) + 1);
		strcpy(str + strlen(str), tmp);
		free(tmp);
		for (size_t n = 0; n < 8; n++) {
			if (get_size_in_bits(buff[n]) <= 64) { // decimal (0xhexa) repr
				ret = asprintf(&tmp, "%s: %lu (%#lx)\n",
					var_name[n], (unsigned long)buff[n], (unsigned long)buff[n]);
			}
			else { // hex:hex:hex repr
				char	*hex = get_hexa_repr(buff[n]);
				if (!hex) {
					free(str);
					return (NULL);
				}
				char *new_hex = add_padding_str(hex, 15 * 3, "    ");
				free(hex);
				if (!new_hex) {
					free(str);
					return (NULL);
				}
				ret = asprintf(&tmp, "%s:\n    %s\n", var_name[n], new_hex);
			}
			if (ret < 0) {
				free(str);
				return (NULL);
			}
			str = realloc(str, strlen(str) + strlen(tmp) + 1);
			strcpy(str + strlen(str), tmp);
			free(tmp);
		}
		return (str);
}

char	*rsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	char	header_private[] = HEADER_PRIVATE;
	char	footer_private[] = FOOTER_PRIVATE;
	size_t		result_size;
	char		*result;

	(void)size;
	DPRINT("rsa(\"%.*s\", %zu)\n", (int)size, query, size);

	result_size = 0;
	result = malloc(result_size);
	if (!result) {
		return (NULL);
	}
	char *start = memmem((char *)query, size, (char *)header_private, strlen(header_private));
	if (!start)
		goto could_not_read;
	start += strlen(header_private);
	char *end = memmem(start, size - ((void *)start - (void *)query), (char *)footer_private, strlen(footer_private));
	if (!end)
		goto could_not_read;
	size_t cipher_size;
	printf("%d\n", end - start);
	uint8_t *cipher_res = (uint8_t *)base64_decode((unsigned char *)start, end - start, &cipher_size);
	if (!cipher_res)
		goto could_not_read;
	struct rsa rsa;
	int ret = read_private_rsa_asn1(&rsa, cipher_res, cipher_size);
	free(cipher_res);
	if (ret)
		goto could_not_read;
	if (options->text) {
		char *str = get_text_from_rsa(&rsa);
		if (!str) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + strlen(str) + 1);
		strcpy(result + result_size, str);
		result_size += strlen(str);
		free(str);
	}
	if (!options->noout) {
		printf("writing RSA key\n");
		size_t len_encoded;
		char *encoded = generate_base64_private_rsa(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qinv, &len_encoded);
		if (!encoded) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + len_encoded);
		if (!result) {
			free(encoded);
			return (NULL);
		}
		memcpy(result + result_size, encoded, len_encoded);
		result_size += len_encoded;
		free(encoded);
	}
	*res_len = result_size;
	return (result);
	could_not_read:
		if (options->in)
			dprintf(STDERR_FILENO, "Could not read private key from %s\n", options->in);
		else
			dprintf(STDERR_FILENO, "Could not read private key from %s\n", "<stdin>");
		free(result);
		return (NULL);
}
