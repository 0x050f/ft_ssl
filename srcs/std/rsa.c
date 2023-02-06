#include "ft_ssl.h"
#include "std.h"

char	*get_hexa_repr(unsigned __int128 n) {
	char				buf[4];
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
		snprintf(buf, 4, "%02x:", ((uint8_t *)&nbis)[0]);
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

static char *var_name[] = {
	[0]		= "modulus",
	[1]		= "publicExponent",
	[2]		= "privateExponent",
	[3]		= "prime1",
	[4]		= "prime2",
	[5]		= "exponent1",
	[6]		= "exponent2",
	[7]		= "coefficient",
	[8]		= "Exponent"
};

char	*get_text_from_rsa(struct rsa *rsa, bool public) {
	unsigned __int128 		buff[sizeof(struct rsa)];
	int						ret;
	char					*tmp;
	char					*str;

	memcpy(buff, rsa, sizeof(struct rsa));
	str = strdup("");
	if (!str)
		return (NULL);
	if (!public)
		ret = asprintf(&tmp, "Private-Key: (%d bit, %d primes)\n", get_size_in_bits(rsa->n), 2);
	else
		ret = asprintf(&tmp, "Public-Key: (%d bit)\n", get_size_in_bits(rsa->n));
	if (ret < 0) {
		free(str);
		return (NULL);
	}
	str = realloc(str, strlen(str) + strlen(tmp) + 1);
	strcpy(str + strlen(str), tmp);
	free(tmp);
	size_t nb = 8;
	if (public)
		nb = 2;
	for (size_t n = 0; n < nb; n++) {
		char *name = (char *)var_name[n];
		if (public && n == 1)
			name = (char *)var_name[8];
		if (get_size_in_bits(buff[n]) <= 64) { // decimal (0xhexa) repr
			ret = asprintf(&tmp, "%s: %lu (%#lx)\n",
				name, (unsigned long)buff[n], (unsigned long)buff[n]);
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
			ret = asprintf(&tmp, "%s:\n    %s\n", name, new_hex);
			free(new_hex);
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

int		check_rsa(
	unsigned __int128 n,
	unsigned __int128 e,
	unsigned __int128 d,
	unsigned __int128 p,
	unsigned __int128 q,
	unsigned __int128 dp,
	unsigned __int128 dq,
	unsigned __int128 qinv
) {
	unsigned __int128 phi;

	if (!check_prime(p, 1.0))
		return (1);
	if (!check_prime(q, 1.0))
		return (1);
	if (n != (unsigned __int128)p * q)
		return (1);
	phi = ((unsigned __int128)p - 1) * (q - 1);
	if (pgcd_binary(phi, e) != 1)
		return (1);
	if ((e * d) % phi != 1) // check inv_mod
		return (1);
	if (dp != d % (p - 1))
		return (1);
	if (dq != d % (q - 1))
		return (1);
	if ((q * qinv) % p != 1)
		return (1);
	return (0);
}

uint8_t		*get_rsa_between_header_footer(
	uint8_t *query,
	size_t size,
	char *header,
	char *footer,
	size_t *cipher_size
) {
	void *start = memmem(query, size, header, strlen(header));
	if (!start)
		return (NULL);
	start += strlen(header);
	void *end = memmem(start, size - (start - (void *)query), footer, strlen(footer));
	if (!end)
		return (NULL);
	uint8_t *cipher_res = (uint8_t *)base64_decode(start, end - start, cipher_size);
	if (!cipher_res)
		return (NULL);
	return (cipher_res);
}

char	*rsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	void		*tmp;
	char		header_private[] = HEADER_PRIVATE;
	char		footer_private[] = FOOTER_PRIVATE;
	char		header_enc_priv[] = HEADER_ENC_PRIVATE;
	char		footer_enc_priv[] = FOOTER_ENC_PRIVATE;
	char		header_public[] = HEADER_PUBLIC;
	char		footer_public[] = FOOTER_PUBLIC;
	uint8_t		*cipher_res = NULL;
	size_t		cipher_size = 0;
	size_t		result_size = 0;
	char		*result = NULL;

	DPRINT("rsa(\"%.*s\", %zu)\n", (int)size, query, size);

	if (options->check && options->pubin) {
		dprintf(STDERR_FILENO, "Only private keys can be checked\n");
		return (NULL);
	}

	result_size = 0;
	result = malloc(result_size);
	if (!result)
		return (NULL);
	if (!options->inform || !strcmp(options->inform, "PEM")) {
		if (options->pubin)
			cipher_res = get_rsa_between_header_footer(query, size, header_public, footer_public, &cipher_size);
		else {
			cipher_res = get_rsa_between_header_footer(query, size, header_private, footer_private, &cipher_size);
			if (!cipher_res) {
				cipher_res = get_rsa_between_header_footer(query, size, header_enc_priv, footer_enc_priv, &cipher_size);
			}
		}
	}
	if (!cipher_res && options->inform && !strcmp(options->inform, "PEM")) {
		goto could_not_read;
	} else if (!cipher_res) { // test as DER
		cipher_size = size;
		cipher_res = malloc(cipher_size);
		if (!cipher_res) {
			free(result);
			return (NULL);
		}
		memcpy(cipher_res, query, cipher_size);
	}
	struct rsa rsa;
	int ret;
	if (!options->pubin) {
		ret = read_encrypted_private_rsa_asn1(&rsa, cipher_res, cipher_size, options->passin);
		if (ret)
			ret = read_private_rsa_asn1(&rsa, cipher_res, cipher_size);
	} else {
		ret = read_public_rsa_asn1(&rsa, cipher_res, cipher_size);
	}
	free(cipher_res);
	if (ret)
		goto could_not_read;
	// Get text from rsa
	if (options->text) {
		tmp = get_text_from_rsa(&rsa, options->pubin);
		if (!tmp) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + strlen(tmp) + 1);
		if (!result) {
			free(tmp);
			return (NULL);
		}
		strcpy(result + result_size, tmp);
		result_size += strlen(tmp);
		free(tmp);
	}
	// Print modulus (n)
	if (options->modulus) {
		asprintf((char **)&tmp, "Modulus=%lX\n", (unsigned long)rsa.n);
		if (!tmp) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + strlen(tmp) + 1);
		if (!result) {
			free(tmp);
			return (NULL);
		}
		strcpy(result + result_size, tmp);
		result_size += strlen(tmp);
		free(tmp);
	}
	// Check the given rsa key
	if (options->check) {
		char buf[256];
		if (get_size_in_bits(rsa.n) > 64 || get_size_in_bits(rsa.e) > 64) {
			dprintf(STDERR_FILENO, "Can't check a key larger than 64 bits\n");
		} else if (!check_rsa(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qinv)) {
			sprintf(buf, "RSA key ok\n");
			result = realloc(result, result_size + strlen(buf) + 1);
			if (!result)
				return (NULL);
			strcpy(result + result_size, buf);
			result_size += strlen(buf);
		} else {
			dprintf(STDERR_FILENO, "RSA key not ok\n");
			*res_len = result_size;
			return (result);
		}
	}
	// Generate and write private rsa key
	if (!options->noout && !options->pubout && !options->pubin) {
		size_t len_encoded;
		char *encoded;
		if (!options->outform || !strcmp(options->outform, "PEM")) {
			encoded = generate_base64_private_rsa(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qinv, options, &len_encoded);
		} else if (!strcmp(options->outform, "DER")) {
			struct asn1 rsa_asn1 = create_asn1_rsa_private_key(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qinv);
			encoded =(char *)rsa_asn1.content;
			len_encoded = rsa_asn1.length;
			if (options->cipher) {
				struct asn1 cipher_asn1;
				if (!strcmp(options->cipher, "des-ecb"))
					cipher_asn1 = create_asn1_des_ecb(encoded, len_encoded, options->passout);
				else if (!strcmp(options->cipher, "des-cbc") || !strcmp(options->cipher, "des"))
					cipher_asn1 = create_asn1_des_cbc(encoded, len_encoded, options->passout);
				free(encoded);
				encoded = (char *)cipher_asn1.content;
				len_encoded = cipher_asn1.length;
			}
		}
		if (!encoded) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + len_encoded);
		if (!result) {
			free(encoded);
			return (NULL);
		}
		dprintf(STDERR_FILENO, "writing RSA key\n");
		memcpy(result + result_size, encoded, len_encoded);
		result_size += len_encoded;
		free(encoded);
	// Generate and write public rsa key
	} else if (!options->noout) {
		size_t len_encoded;
		char *encoded;
		if (!options->outform || !strcmp(options->outform, "PEM")) {
			encoded = generate_base64_public_rsa(rsa.n, rsa.e, options, &len_encoded);
		} else if (!strcmp(options->outform, "DER")) {
			struct asn1 rsa_asn1 = create_asn1_rsa_public_key(rsa.n, rsa.e);
			encoded = (char *)rsa_asn1.content;
			len_encoded = rsa_asn1.length;
		}
		if (!encoded) {
			free(result);
			return (NULL);
		}
		dprintf(STDERR_FILENO, "writing RSA key\n");
		result = realloc(result, result_size + len_encoded);
		if (!result) {
			free(encoded);
			return (NULL);
		}
		memcpy(result + result_size, encoded, len_encoded);
		result_size += len_encoded;
		free(encoded);
	}
	// Update result size
	*res_len = result_size;
	return (result);
	could_not_read:
		if (options->in && !options->pubin)
			dprintf(STDERR_FILENO, "Could not read private key from %s\n", options->in);
		else if (!options->pubin)
			dprintf(STDERR_FILENO, "Could not read private key from %s\n", "<stdin>");
		else if (options->in)
			dprintf(STDERR_FILENO, "Could not read public key from %s\n", options->in);
		else
			dprintf(STDERR_FILENO, "Could not read public key from %s\n", "<stdin>");
		free(result);
		return (NULL);
}
