#include "ft_ssl.h"
#include "std.h"

struct __attribute__((__packed__)) rsa {
	unsigned __int128	n;
	unsigned __int128	e;
	unsigned __int128	d;
	unsigned __int128	p;
	unsigned __int128	q;
	unsigned __int128	dp;
	unsigned __int128	dq;
	unsigned __int128	qinv;
};

int		check_asn1_sequence(uint8_t *asn1, size_t size) {
	if (asn1[0] != ID_SEQ)
		return (1);
	if (asn1[1] & 0x80) {
		dprintf(STDERR_FILENO, "Unsupported size of key file (< 128 bits keys supported)\n");
		return (1);
	}
	if (asn1[1] > size - 2)
		return (1);
	return (0);
}

int		check_asn1_integer(uint8_t *asn1, size_t size) {
	if (asn1[0] != ID_INTEGER) {
		return (1);
	}
	if (asn1[1] & 0x80) {
		dprintf(STDERR_FILENO, "Unsupported size of key file (< 128 bits keys supported)\n");
		return (1);
	}
	if (asn1[1] > size - 2) {
		return (1);
	}
	return (0);
}

int			check_asn1_octet(uint8_t *asn1, size_t size) {
	size_t i = 0;

	if (asn1[i++] != ID_OCTET)
		return (1);
	if (asn1[i] & 0x80) {
		dprintf(STDERR_FILENO, "Unsupported size of key file (< 128 bits keys supported)\n");
		return (1);
	}
	size_t octet_size = asn1[i++];
	if (octet_size < size - 2) {
		return (1);
	}
	if (check_asn1_sequence(&asn1[i], size - i))
		return (1);
	i += 2;
	while (i - 2 < octet_size) {
		if (check_asn1_integer(&asn1[i], size - i))
			return (1);
		size_t integer_size = asn1[i + 1];
		i += integer_size + 2;
	}
	if (i - 2 != octet_size)
		return (1);
	return (0);
}

unsigned __int128		get_asn1_integer(uint8_t *asn1) {
	unsigned __int128 nb;
	size_t size = asn1[1];

	asn1 += 2;
	nb = 0;
	for (size_t i = 0; i < size; i++) {
		nb *= 256;
		nb += asn1[i];
	}
	return (nb);
}

int			parse_rsa_asn1_octet(struct rsa *rsa, uint8_t *asn1, int nb) {
	uint8_t			buffer[4096];
	size_t			i = 0;
	size_t			j = 0;

	size_t octet_size = asn1[i + 3];
	i += 4; // skip octet and sequence
	i += 3; // skip integer 0
	while (i - 2 < octet_size) {
		unsigned __int128 result = get_asn1_integer(&asn1[i]);
		memcpy(&buffer[j], &result, 16);
		size_t integer_size = asn1[i + 1];
		i += integer_size + 2;
		j += 16;
	}
	if ((int)j / 16 != nb) // wrong number of nb in octet
		return (1);
	memcpy(rsa, &buffer, j);
	return (0);
}

uint8_t		*check_rsa_asn1_header(uint8_t *asn1, size_t size) {
	if (size < 18)
		return (NULL);
	if (asn1[0] != ID_SEQ)
		return (NULL);
	if (asn1[1] & 0x80 && asn1[1] > size - 2)
		return (NULL);
	uint8_t *tmp;
	tmp = memmem(asn1, size, INTEGER_0, 3);
	if (!tmp || size - (tmp - asn1) < strlen(RSA_OBJECTID) + 4)
		return (NULL);
	asn1 = tmp + 3;
	if (asn1[0] != ID_SEQ)
		return (NULL);
	if (asn1[2] != ID_OBJECT)
		return (NULL);
	if (memcmp(&asn1[4], RSA_OBJECTID, strlen(RSA_OBJECTID)))
		return (NULL);
	if (asn1[1] > size - 4)
		return (NULL);
	return (asn1 + asn1[1] + 2);
}

int		read_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size) {
	uint8_t *tmp;

	tmp = check_rsa_asn1_header(asn1, size);
	if (!tmp)
		return (1);
	if (check_asn1_octet(tmp, size - (tmp - asn1)))
		return (1);
	if (parse_rsa_asn1_octet(prv, tmp, 8))
		return (1);
	return (0);
}

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
	char *start = strstr((char *)query, (char *)header_private);
	if (!start)
		goto could_not_read;
	start += strlen(header_private);
	char *end = strstr(start, (char *)footer_private);
	if (!end)
		goto could_not_read;
	size_t cipher_size;
	uint8_t *cipher_res = (uint8_t *)base64_decode((unsigned char *)start, end - start, &cipher_size);
	if (!cipher_res)
		goto could_not_read;
	struct rsa rsa;
	int ret = read_private_rsa_asn1(&rsa, cipher_res, cipher_size);
	if (ret)
		goto could_not_read;
	if (options->text) {
		char *str;

		ret = asprintf(&str, "Private-Key: (%d bit, %d primes)\n", get_size_in_bits(rsa.n), 2);
		if (ret < 0) {
			free(result);
			return (NULL);
		}
		result = realloc(result, result_size + strlen(str));
		strcpy(result + result_size, str);
		result_size += strlen(str);
		free(str);
		char *hex = get_hexa_repr(rsa.n);
		ret = asprintf(&str, "modulus:\n    %s\n", hex);
		free(hex);
		result = realloc(result, result_size + strlen(str));
		strcpy(result + result_size, str);
		result_size += strlen(str);
		free(str);
		/*
		ret = asprintf(&str, "Private-Key: (%d bit, %d primes)\n)", );
		asprintf(&str, "Private-Key: (%d bit, %d primes)\n
modulus: abc\n
publicExponent: %d (%x)\n
privateExponent: abc\n
prime1: %llu (%llx)\n
prime2: %llu");
		*/
	}
	if (!options->noout) {
		printf("writing RSA key\n");
		size_t len_encoded;
		char *encoded = generate_base64_private_rsa(rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qinv, &len_encoded);
		result = realloc(result, result_size + len_encoded);
		if (!result)
			return (NULL);
		memcpy(result + result_size, encoded, len_encoded);
		result_size += len_encoded;
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
