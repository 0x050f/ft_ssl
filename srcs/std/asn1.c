#include "ft_ssl.h"
#include "std.h"

int			add_integer_asn1(uint8_t *dst, unsigned __int128 nb) {
	unsigned __int128	tmp;
	size_t				size;

	size = 1;
	tmp = nb;
	while (tmp / 0xff) {
		size++;
		tmp /= 0xff;
	}
	*dst++ = ID_INTEGER;
	*dst++ = size;
	for (int i = size - 1; i >= 0; i--) {
		*dst++ = ((uint8_t *)&nb)[i];
	}
	return (2 + size);
}

struct asn1		create_asn1_rsa_public_key (
	unsigned __int128 n,
	unsigned __int128 e
) {
	struct asn1		result;
	uint8_t			tmp[4096];
	size_t			i = 0;

	// MASTER SEQUENCE
	tmp[i] = ID_SEQ;
	// fill sequence size at the end
	i += 2;

	// SEQUENCE OBJECT
	tmp[i++] = ID_SEQ;
	tmp[i++] = strlen(RSA_OBJECTID) + 2; // + 4;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(RSA_OBJECTID);

	memcpy(tmp + i, RSA_OBJECTID, strlen(RSA_OBJECTID));
	i += strlen(RSA_OBJECTID);

//	tmp[i++] = ID_NULL; // not needed but provided by openssl
//	tmp[i++] = 0x0;

	// BIT STRING + SEQUENCE
	tmp[i++] = ID_BIT;
	size_t		idx_octet = i++;
    tmp[i++] = 0x0;

	tmp[i++] = ID_SEQ;
	size_t		idx_seq = i++;

	i += add_integer_asn1(tmp + i, n);
	i += add_integer_asn1(tmp + i, e);

	tmp[idx_seq] = i - idx_seq - 1;
	tmp[idx_octet] = i - idx_octet - 1;
	tmp[1] = i - 2;

	result.length = i;
	result.content = malloc(i * sizeof(uint8_t));
	if (!result.content) {
		return (result);
	}
	memcpy(result.content, tmp, i);
	return (result);
}

struct asn1		create_asn1_rsa_private_key(
	unsigned __int128 n,
	unsigned __int128 e,
	unsigned __int128 d,
	unsigned __int128 p,
	unsigned __int128 q,
	unsigned __int128 dp,
	unsigned __int128 dq,
	unsigned __int128 qinv
) {
	struct asn1		result;
	uint8_t			tmp[4096];
	size_t			i = 0;

	// MASTER SEQUENCE
	tmp[i] = ID_SEQ;
	// fill sequence size at the end
	i += 2;

	i += add_integer_asn1(tmp + i, 0);

	// SEQUENCE OBJECT
	tmp[i++] = ID_SEQ;
	tmp[i++] = strlen(RSA_OBJECTID) + 2; // + 4;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(RSA_OBJECTID);

	memcpy(tmp + i, RSA_OBJECTID, strlen(RSA_OBJECTID));
	i += strlen(RSA_OBJECTID);

//	tmp[i++] = ID_NULL; // not needed but provided by openssl
//	tmp[i++] = 0x0;

	// OCTET STRING + SEQUENCE
	tmp[i++] = ID_OCTET;
	size_t		idx_octet = i++;

	tmp[i++] = ID_SEQ;
	size_t		idx_seq = i++;

	i += add_integer_asn1(tmp + i, 0);
	i += add_integer_asn1(tmp + i, n);
	i += add_integer_asn1(tmp + i, e);
	i += add_integer_asn1(tmp + i, d);
	i += add_integer_asn1(tmp + i, p);
	i += add_integer_asn1(tmp + i, q);
	i += add_integer_asn1(tmp + i, dp);
	i += add_integer_asn1(tmp + i, dq);
	i += add_integer_asn1(tmp + i, qinv);
	tmp[idx_seq] = i - idx_seq - 1;
	tmp[idx_octet] = i - idx_octet - 1;
	tmp[1] = i - 2;

	result.length = i;
	result.content = malloc(i * sizeof(uint8_t));
	if (!result.content) {
		return (result);
	}
	memcpy(result.content, tmp, i);
	return (result);
}

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

int			parse_rsa_asn1_bit(struct rsa *rsa, uint8_t *asn1, int nb) {
	uint8_t			buffer[4096];
	size_t			i = 0;
	size_t			j = 0;

	size_t bit_size = asn1[i + 4];
	i += 5; // skip bit and sequence
	while (i - 2 < bit_size) {
		unsigned __int128 result = get_asn1_integer(&asn1[i]);
		memcpy(&buffer[j], &result, 16);
		size_t integer_size = asn1[i + 1];
		i += integer_size + 2;
		j += 16;
	}
	if ((int)j / 16 != nb) // wrong number of nb in bit
		return (1);
	memcpy(rsa, &buffer, j);
	return (0);
}

int			check_asn1_bit(uint8_t *asn1, size_t size) {
	size_t i = 0;

	if (asn1[i++] != ID_BIT)
		return (1);
	if (asn1[i] & 0x80) {
		dprintf(STDERR_FILENO, "Unsupported size of key file (< 128 bits keys supported)\n");
		return (1);
	}
	size_t bit_size = asn1[i++];
	if (bit_size < size - 2)
		return (1);
	if (asn1[i++] != 0x0)
		return (1);
	if (check_asn1_sequence(&asn1[i], size - i))
		return (1);
	i += 2;
	while (i - 2 < bit_size) {
		if (check_asn1_integer(&asn1[i], size - i))
			return (1);
		size_t integer_size = asn1[i + 1];
		i += integer_size + 2;
	}
	if (i - 2 != bit_size)
		return (1);
	return (0);
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

uint8_t		*check_rsa_asn1_pub_header(uint8_t *asn1, size_t size) {
	if (size < 18)
		return (NULL);
	if (asn1[0] != ID_SEQ)
		return (NULL);
	if (asn1[1] & 0x80 && asn1[1] > size - 2)
		return (NULL);
	asn1 += 2;
	if (asn1[0] != ID_SEQ)
		return (NULL);
	if (asn1[2] != ID_OBJECT)
		return (NULL);
	if (memcmp(&asn1[4], RSA_OBJECTID, strlen(RSA_OBJECTID)))
		return (NULL);
	if (asn1[1] > size - 2)
		return (NULL);
	return (asn1 + asn1[1] + 2);
}

uint8_t		*check_rsa_asn1_priv_header(uint8_t *asn1, size_t size) {
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

int		read_public_rsa_asn1(struct rsa *pub, uint8_t *asn1, size_t size) {
	uint8_t *tmp;

	tmp = check_rsa_asn1_pub_header(asn1, size);
	if (!tmp)
		return (1);
	if (check_asn1_bit(tmp, size - (tmp - asn1)))
		return (1);
	if (parse_rsa_asn1_bit(pub, tmp, 2))
		return (1);
	return (0);
}

int		read_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size) {
	uint8_t *tmp;

	tmp = check_rsa_asn1_priv_header(asn1, size);
	if (!tmp)
		return (1);
	if (check_asn1_octet(tmp, size - (tmp - asn1)))
		return (1);
	if (parse_rsa_asn1_octet(prv, tmp, 8))
		return (1);
	return (0);
}
