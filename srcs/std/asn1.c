#include "ft_ssl.h"
#include "std.h"

int			get_size_in_byte(unsigned __int128 n) {
	int count = 1;

	while (n / 0xff) {
		count++;
		n /= 0xff;
	}
	return (count);
}

unsigned __int128		inv_nb(unsigned __int128 n) {
	unsigned __int128	ret;
	int					nb_bytes;
	int					i;

	i = 0;
	nb_bytes = get_size_in_byte(n);
	for (int j = nb_bytes - 1; j >= 0; j--) {
		((uint8_t *)&ret)[i++] = ((uint8_t *)&n)[j];
	}
	return (ret);
}

void		embed_asn1_elem(struct asn1 *asn1, uint8_t elem) {
	size_t		add_size;
	int		nb_bytes;

	if (!asn1->content)
		return ;
	nb_bytes = get_size_in_byte(asn1->length);
	add_size = (nb_bytes > 1) ? nb_bytes + 2 : nb_bytes + 1;
	asn1->content = realloc(asn1->content, add_size + asn1->length);
	if (!asn1->content)
		return ;
	memmove(asn1->content + add_size, asn1->content, asn1->length);
	int i = 0;
	asn1->content[i++] = elem;
	if (nb_bytes > 1)
		asn1->content[i++] = 0x80 + nb_bytes;
	for (int j = nb_bytes - 1; j >= 0; j--) {
		asn1->content[i++] = ((uint8_t *)&(asn1->length))[j];
	}
	asn1->length += add_size;
}

void		append_asn1_elem(struct asn1 *asn1, uint8_t elem,
void *content, size_t content_size) {
	if (!asn1->content || !content)
		return ;
	struct asn1 copy;

	copy.content = malloc(content_size);
	copy.length = content_size;
	if (!copy.content) {
		free(asn1->content);
		asn1->content = NULL;
		return ;
	}
	memcpy(copy.content, content, content_size);
	embed_asn1_elem(&copy, elem);
	if (!copy.content) {
		free(asn1->content);
		asn1->content = NULL;
		return ;
	}
	asn1->content = realloc(asn1->content, asn1->length + copy.length);
	if (!asn1->content) {
		free(copy.content);
		return ;
	}
	memcpy(asn1->content + asn1->length, copy.content, copy.length);
	asn1->length += copy.length;
	free(copy.content);
}

void		prepend_asn1_elem(struct asn1 *asn1, uint8_t elem,
void *content, size_t content_size) {
	if (!asn1->content || !content)
		return ;
	struct asn1 copy;

	copy.content = malloc(content_size);
	copy.length = content_size;
	if (!copy.content) {
		free(asn1->content);
		asn1->content = NULL;
		return ;
	}
	memcpy(copy.content, content, content_size);
	embed_asn1_elem(&copy, elem);
	if (!copy.content) {
		free(asn1->content);
		asn1->content = NULL;
		return ;
	}
	asn1->content = realloc(asn1->content, asn1->length + copy.length);
	if (!asn1->content) {
		free(copy.content);
		return ;
	}
	memmove(asn1->content + copy.length, asn1->content, asn1->length);
	memcpy(asn1->content, copy.content, copy.length);
	asn1->length += copy.length;
	free(copy.content);
}

/*
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

struct asn1		create_asn1_des_ecb(
	char		*payload,
	size_t		size
) {
	int				ret;
	struct asn1		result;
	uint8_t			tmp[4096];
	size_t			i = 0;
	int				iter = 2048;
	uint8_t			salt[8];
	uint64_t		key;
	char			*password;
	uint8_t			*cipher;
	size_t			cipher_size;

	memset(&result, 0, sizeof(struct asn1));
	ret = get_password_stdin("des-ecb", &password, CMODE_ENCRYPT);
	if (ret)
		return (result);
	if (get_key_encrypt(&key, salt, NULL, NULL, NULL, password, iter) < 0) {
		free(password);
		return (result);
	}
	free(password);
	cipher = (uint8_t *)des_ecb_encrypt_from_key((unsigned char *)payload, size, key, &cipher_size);
	if (!cipher)
		return (result);

	// MASTER SEQUENCE
	tmp[i] = ID_SEQ;
	// fill sequence size at the end
	i += 2;

	// SEQUENCE OBJECT
	tmp[i] = ID_SEQ;
	// fill sequence size at the end
	i += 2;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(PBES2_OBJECTID);

	memcpy(tmp + i, PBES2_OBJECTID, strlen(PBES2_OBJECTID));
	i += strlen(PBES2_OBJECTID);

	tmp[i++] = ID_SEQ;
	size_t j = i; // fill sequence size later
	i++;

	tmp[i++] = ID_SEQ;
	size_t k = i; // fill sequence size later
	i++;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(PBKDF2_OBJECTID);

	memcpy(tmp + i, PBKDF2_OBJECTID, strlen(PBKDF2_OBJECTID));
	i += strlen(PBKDF2_OBJECTID);

	tmp[i++] = ID_SEQ;
	size_t l = i; // fill sequence size later
	i++;

	// OCTET STRING - Salt
	tmp[i++] = ID_OCTET;
	tmp[i++] = 0x8;

	for (int j = 0x8 - 1; j >= 0; j--) {
		tmp[i++] = ((uint8_t *)&salt)[j];
	}

	i += add_integer_asn1(tmp + i, iter);

	tmp[i++] = ID_SEQ;
	tmp[i++] = strlen(HASHMACSHA256_OBJECTID);

	memcpy(tmp + i, HASHMACSHA256_OBJECTID, strlen(HASHMACSHA256_OBJECTID));
	i += strlen(HASHMACSHA256_OBJECTID);

	tmp[i++] = ID_NULL;
	tmp[i++] = 0x0;

	tmp[l] = i - l;
	tmp[k] = i - k;

	tmp[i++] = ID_SEQ;
	tmp[i++] = strlen(DESECB_OBJECTID) + 2 + 2;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(DESECB_OBJECTID);

	memcpy(tmp + i, DESECB_OBJECTID, strlen(DESECB_OBJECTID));
	i += strlen(DESECB_OBJECTID);

	tmp[i++] = ID_OCTET;
	tmp[i++] = 0x0;

	tmp[j] = i - j;
	tmp[3] = i - 4;

	tmp[i++] = ID_OCTET;
	tmp[i++] = cipher_size;

	memcpy(tmp + i, cipher, cipher_size);
	i += cipher_size;
	free(cipher);

	tmp[1] = i - 2;

	result.length = i;

	result.content = malloc(i * sizeof(uint8_t));
	if (!result.content) {
		return (result);
	}
	memcpy(result.content, tmp, i);
	return (result);
}
*/

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
	unsigned __int128 tmp;
	struct asn1		asn1;

	bzero(&asn1, sizeof(struct asn1));
	asn1.content = malloc(0);
	if (!asn1.content)
		return (asn1);

	append_asn1_elem(&asn1, ID_INTEGER, "\x00", 1);

	tmp = inv_nb(n);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(n));
	tmp = inv_nb(e);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(e));
	tmp = inv_nb(d);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(d));
	tmp = inv_nb(p);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(p));
	tmp = inv_nb(q);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(q));
	tmp = inv_nb(dp);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(dp));
	tmp = inv_nb(dq);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(dq));
	tmp = inv_nb(qinv);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(qinv));

	embed_asn1_elem(&asn1, ID_SEQ);
	embed_asn1_elem(&asn1, ID_OCTET);

	struct asn1		header;

	bzero(&header, sizeof(struct asn1));
	header.content = malloc(0);
	if (!header.content) {
		free(asn1.content);
		asn1.content = NULL;
		return (asn1);
	}
	append_asn1_elem(&header, ID_OBJECT, RSA_OBJECTID, strlen(RSA_OBJECTID));
	//header.content = append_asn1_elem(header.content, &header.length, ID_NULL, "\x00", 1); // not needed but provided by openssl

	prepend_asn1_elem(&asn1, ID_SEQ, header.content, header.length);
	free(header.content);

	prepend_asn1_elem(&asn1, ID_INTEGER, "\x00", 1);
	embed_asn1_elem(&asn1, ID_SEQ);
	return (asn1);
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
