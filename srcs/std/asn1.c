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

void	*swap_bytes(void *dst, size_t len) {
	uint8_t		*in, tmp;

	in = dst;
	for (size_t i = 0; i < len / 2; i++) {
		tmp = in[i];
		in[i] = in[len - i - 1];
		in[len - i - 1] = tmp;
	}
	return (dst);
}

void		embed_asn1_elem(struct asn1 *asn1, uint8_t elem) {
	size_t		add_size;
	int		nb_bytes;

	if (!asn1->content)
		return ;
	nb_bytes = get_size_in_byte(asn1->length);
	add_size = (nb_bytes > 1) ? nb_bytes + 2 : nb_bytes + 1;
	if (nb_bytes == 1 && asn1->length >= 0x80) // if need 0x80 byte
		add_size += 1;
	asn1->content = realloc(asn1->content, add_size + asn1->length);
	if (!asn1->content)
		return ;
	memmove(asn1->content + add_size, asn1->content, asn1->length);
	int i = 0;
	asn1->content[i++] = elem;
	if (nb_bytes > 1 || asn1->length >= 0x80)
		asn1->content[i++] = 0x80 + nb_bytes;
	for (int j = nb_bytes - 1; j >= 0; j--)
		asn1->content[i++] = ((uint8_t *)&(asn1->length))[j];
	if (elem == ID_BIT)
		asn1->content[i] = '\x00';
	asn1->length += add_size;
}

void		append_asn1_content(struct asn1 *asn1, void *content, size_t size) {
	if (!asn1->content || !content)
		return ;

	asn1->content = realloc(asn1->content, asn1->length + size);
	if (!asn1->content) {
		return ;
	}
	memcpy(asn1->content + asn1->length, content, size);
	asn1->length += size;
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
	append_asn1_content(asn1, copy.content, copy.length);
	free(copy.content);
}

void		prepend_asn1_content(struct asn1 *asn1, void *content, size_t size) {
	if (!asn1->content || !content)
		return ;
	asn1->content = realloc(asn1->content, asn1->length + size);
	if (!asn1->content) {
		return ;
	}
	memmove(asn1->content + size, asn1->content, asn1->length);
	memcpy(asn1->content, content, size);
	asn1->length += size;
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
	prepend_asn1_content(asn1, copy.content, copy.length);
	free(copy.content);
}

struct asn1		create_asn1_rsa_public_key (
	unsigned __int128 n,
	unsigned __int128 e
) {
	unsigned __int128 tmp;
	struct asn1		asn1;

	bzero(&asn1, sizeof(struct asn1));
	asn1.content = malloc(0);
	if (!asn1.content)
		return (asn1);

	tmp = n;
	swap_bytes(&tmp, get_size_in_byte(n));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(n));
	tmp = e;
	swap_bytes(&tmp, get_size_in_byte(e));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(e));

	embed_asn1_elem(&asn1, ID_SEQ);
	prepend_asn1_content(&asn1, "\x00", 1);
	embed_asn1_elem(&asn1, ID_BIT);

	struct asn1		header;

	bzero(&header, sizeof(struct asn1));
	header.content = malloc(0);
	if (!header.content) {
		free(asn1.content);
		asn1.content = NULL;
		return (asn1);
	}
	append_asn1_elem(&header, ID_OBJECT, RSA_OBJECTID, strlen(RSA_OBJECTID));
//	append_asn1_elem(&header, ID_NULL, "", 0); // not needed but provided by openssl

	prepend_asn1_elem(&asn1, ID_SEQ, header.content, header.length);
	free(header.content);

	embed_asn1_elem(&asn1, ID_SEQ);
	return (asn1);
}

struct asn1		create_asn1_des_cbc(
	char		*payload,
	size_t		size
) {
	int						ret;
	struct asn1				asn1;
	int						iter = 2048;
	uint8_t					salt[8];
	uint64_t				key;
	uint64_t				iv;
	uint64_t				tmp;
	char					*password;
	uint8_t					*cipher;
	size_t					cipher_size;

	// Compute cipher
	memset(&asn1, 0, sizeof(struct asn1));
	ret = get_password_stdin("des-cbc", &password, CMODE_ENCRYPT);
	if (ret)
		return (asn1);
	if (get_key_encrypt(&key, salt, NULL, NULL, &iv, password, iter) < 0) {
		free(password);
		return (asn1);
	}
	free(password);
	cipher = (uint8_t *)des_cbc_encrypt_from_key_iv((unsigned char *)payload, size, key, iv, &cipher_size);
	if (!cipher)
		return (asn1);

	asn1.content = malloc(0);
	if (!asn1.content) {
		free(cipher);
		return (asn1);
	}

	// DESECB SEQUENCE
	append_asn1_elem(&asn1, ID_OBJECT, DESCBC_OBJECTID, strlen(DESCBC_OBJECTID));
	
	tmp = iv;
	swap_bytes(&tmp, get_size_in_byte(iv));
	append_asn1_elem(&asn1, ID_OCTET, &tmp, get_size_in_byte(iv));
	embed_asn1_elem(&asn1, ID_SEQ);

	struct asn1 header;

	bzero(&header, sizeof(struct asn1));
	header.content = malloc(0);
	if (!header.content) {
		free(cipher);
		free(asn1.content);
		asn1.content = NULL;
		return (asn1);
	}
	// HASHMAC_SHA256
	append_asn1_elem(&header, ID_OBJECT, HASHMACSHA256_OBJECTID, strlen(HASHMACSHA256_OBJECTID));
	append_asn1_elem(&header, ID_NULL, "", 0);
	embed_asn1_elem(&header, ID_SEQ);

	// PBKDF2 PARAMS
	tmp = iter;
	swap_bytes(&tmp, get_size_in_byte(iter));
	prepend_asn1_elem(&header, ID_INTEGER, &tmp, get_size_in_byte(iter));
	prepend_asn1_elem(&header, ID_OCTET, salt, 8);
	embed_asn1_elem(&header, ID_SEQ);

	// PBKDF2
	prepend_asn1_elem(&header, ID_OBJECT, PBKDF2_OBJECTID, strlen(PBKDF2_OBJECTID));
	embed_asn1_elem(&header, ID_SEQ);

	prepend_asn1_content(&asn1, header.content, header.length);
	free(header.content);
	embed_asn1_elem(&asn1, ID_SEQ);

	// PBES2
	prepend_asn1_elem(&asn1, ID_OBJECT, PBES2_OBJECTID, strlen(PBES2_OBJECTID));
	embed_asn1_elem(&asn1, ID_SEQ);

	append_asn1_elem(&asn1, ID_OCTET, cipher, cipher_size);
	free(cipher);

	embed_asn1_elem(&asn1, ID_SEQ);
	return (asn1);
}

struct asn1		create_asn1_des_ecb(
	char		*payload,
	size_t		size
) {
	int						ret;
	struct asn1				asn1;
	int						iter = 2048;
	uint64_t				tmp;
	uint8_t					salt[8];
	uint64_t				key;
	char					*password;
	uint8_t					*cipher;
	size_t					cipher_size;

	// Compute cipher
	memset(&asn1, 0, sizeof(struct asn1));
	ret = get_password_stdin("des-ecb", &password, CMODE_ENCRYPT);
	if (ret)
		return (asn1);
	if (get_key_encrypt(&key, salt, NULL, NULL, NULL, password, iter) < 0) {
		free(password);
		return (asn1);
	}
	free(password);
	cipher = (uint8_t *)des_ecb_encrypt_from_key((unsigned char *)payload, size, key, &cipher_size);
	if (!cipher)
		return (asn1);

	asn1.content = malloc(0);
	if (!asn1.content) {
		free(cipher);
		return (asn1);
	}

	// DESECB SEQUENCE
	append_asn1_elem(&asn1, ID_OBJECT, DESECB_OBJECTID, strlen(DESECB_OBJECTID));
	append_asn1_elem(&asn1, ID_OCTET, "", 0);
	embed_asn1_elem(&asn1, ID_SEQ);

	struct asn1 header;

	bzero(&header, sizeof(struct asn1));
	header.content = malloc(0);
	if (!header.content) {
		free(cipher);
		free(asn1.content);
		asn1.content = NULL;
		return (asn1);
	}
	// HASHMAC_SHA256
	append_asn1_elem(&header, ID_OBJECT, HASHMACSHA256_OBJECTID, strlen(HASHMACSHA256_OBJECTID));
	append_asn1_elem(&header, ID_NULL, "", 0);
	embed_asn1_elem(&header, ID_SEQ);

	// PBKDF2 PARAMS
	tmp = iter;
	swap_bytes(&tmp, get_size_in_byte(iter));
	prepend_asn1_elem(&header, ID_INTEGER, &tmp, get_size_in_byte(iter));
	prepend_asn1_elem(&header, ID_OCTET, salt, 8);
	embed_asn1_elem(&header, ID_SEQ);

	// PBKDF2
	prepend_asn1_elem(&header, ID_OBJECT, PBKDF2_OBJECTID, strlen(PBKDF2_OBJECTID));
	embed_asn1_elem(&header, ID_SEQ);

	prepend_asn1_content(&asn1, header.content, header.length);
	free(header.content);
	embed_asn1_elem(&asn1, ID_SEQ);

	// PBES2
	prepend_asn1_elem(&asn1, ID_OBJECT, PBES2_OBJECTID, strlen(PBES2_OBJECTID));
	embed_asn1_elem(&asn1, ID_SEQ);

	append_asn1_elem(&asn1, ID_OCTET, cipher, cipher_size);
	free(cipher);

	embed_asn1_elem(&asn1, ID_SEQ);
	return (asn1);
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
	unsigned __int128 tmp;
	struct asn1		asn1;

	bzero(&asn1, sizeof(struct asn1));
	asn1.content = malloc(0);
	if (!asn1.content)
		return (asn1);

	append_asn1_elem(&asn1, ID_INTEGER, "\x00", 1);

	tmp = n;
	swap_bytes(&tmp, get_size_in_byte(n));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(n));
	tmp = e;
	swap_bytes(&tmp, get_size_in_byte(e));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(e));
	tmp = d;
	swap_bytes(&tmp, get_size_in_byte(d));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(d));
	tmp = p;
	swap_bytes(&tmp, get_size_in_byte(p));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(p));
	tmp = q;
	swap_bytes(&tmp, get_size_in_byte(q));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(q));
	tmp = dp;
	swap_bytes(&tmp, get_size_in_byte(dp));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(dp));
	tmp = dq;
	swap_bytes(&tmp, get_size_in_byte(dq));
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(dq));
	tmp = qinv;
	swap_bytes(&tmp, get_size_in_byte(qinv));
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
//	append_asn1_elem(&header, ID_NULL, "", 0); // not needed but provided by openssl

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

uint8_t		*check_asn1_elem(uint8_t *asn1, size_t *size, uint8_t elem, void *value, size_t value_size, bool skip) {
	size_t	elem_size = 0;
	int		i = 0;

	if (!asn1)
		return (NULL);
	if (*size < 2)
		return (NULL);
	if (asn1[i++] != elem)
		return (NULL);
	if (asn1[i] & 0x80) {
		size_t nb_size = (asn1[i++] ^ 0x80);
		if (nb_size + 2 >= *size)
			return (NULL);
		memcpy(&elem_size, &asn1[i], nb_size);
		swap_bytes(&elem_size, nb_size);
		i += nb_size;
	} else {
		elem_size = asn1[i++];
	}
	if (elem_size + i > *size)
		return (NULL);
	if (value) {
		if (elem_size != value_size)
			return (NULL);
		if (memcmp(&asn1[i], value, elem_size))
			return (NULL);
	}
	if (skip)
		i += elem_size;
	*size -= i;
	return (&asn1[i]);
}

void		*get_asn1_elem(uint8_t *asn1, size_t size, uint8_t elem, size_t *size_content) {
	void		*content;
	size_t		elem_size = 0;
	int			i = 0;

	if (!asn1)
		return (NULL);
	if (size < 2)
		return (NULL);
	if (asn1[i++] != elem)
		return (NULL);
	if (asn1[i] & 0x80) {
		size_t nb_size = (asn1[i++] ^ 0x80);
		if (nb_size + 2 >= size)
			return (NULL);
		memcpy(&elem_size, &asn1[i], nb_size);
		swap_bytes(&elem_size, nb_size);
		i += nb_size;
	} else {
		elem_size = asn1[i++];
	}
	if (elem_size + i > size)
		return (NULL);
	content = malloc(elem_size);
	if (!content)
		return (NULL);
	memcpy(content, &asn1[i], elem_size);
	*size_content = elem_size;
	return (content);
}

uint8_t		*parse_rsa_asn1_encrypted_priv_header(uint8_t *asn1, size_t size, uint8_t salt[8], int *iter, uint64_t *iv) {
	void		*res;
	size_t		elem_size;
	size_t		tmp_size;
	uint8_t		*tmp;
	uint8_t		*type;

	tmp = asn1;
	tmp_size = size;
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, PBES2_OBJECTID, strlen(PBES2_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, PBKDF2_OBJECTID, strlen(PBKDF2_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	res = get_asn1_elem(tmp, tmp_size, ID_OCTET, &elem_size);
	if (!res)
		return (NULL);
	bzero(salt, 8);
	memcpy(salt, res, elem_size);
	free(res);

	tmp = check_asn1_elem(tmp, &tmp_size, ID_OCTET, NULL, 0, true);
	*iter = 0;
	res = get_asn1_elem(tmp, tmp_size, ID_INTEGER, &elem_size);
	if (!res)
		return (NULL);
	b_memcpy(iter, res, elem_size);
	free(res);

	tmp = check_asn1_elem(tmp, &tmp_size, ID_INTEGER, NULL, 0, true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, HASHMACSHA256_OBJECTID, strlen(HASHMACSHA256_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_NULL, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	size_t copy_size = tmp_size;
	type = check_asn1_elem(tmp, &copy_size, ID_OBJECT, DESCBC_OBJECTID, strlen(DESCBC_OBJECTID), false);
	if (!type) {
		size_t copy_size = tmp_size;
		type = check_asn1_elem(tmp, &copy_size, ID_OBJECT, DESECB_OBJECTID, strlen(DESECB_OBJECTID), false);
		if (type)
			tmp = type + strlen(DESECB_OBJECTID);
		else
			tmp = NULL;
	} else {
		tmp = type + strlen(DESCBC_OBJECTID);
	}
	tmp_size = copy_size;
	res = get_asn1_elem(tmp, tmp_size, ID_OCTET, &elem_size);
	*iv = 0;
	if (!res)
		return (NULL);
	b_memcpy(iv, res, elem_size);
	free(res);
	return (type);
}

uint8_t		*check_rsa_asn1_encrypted_priv_header(uint8_t *asn1, size_t size) {
	size_t		tmp_size;
	uint8_t		*tmp;

	tmp = asn1;
	tmp_size = size;
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, PBES2_OBJECTID, strlen(PBES2_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, PBKDF2_OBJECTID, strlen(PBKDF2_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OCTET, NULL, 0, true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_INTEGER, NULL, 0, true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, HASHMACSHA256_OBJECTID, strlen(HASHMACSHA256_OBJECTID), true);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_NULL, NULL, 0, false);
	tmp = check_asn1_elem(tmp, &tmp_size, ID_SEQ, NULL, 0, false);
	uint8_t *test;
	test = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, DESECB_OBJECTID, strlen(DESECB_OBJECTID), true);
	if (!test)
		test = check_asn1_elem(tmp, &tmp_size, ID_OBJECT, DESCBC_OBJECTID, strlen(DESCBC_OBJECTID), true);
	tmp = test;
	tmp = check_asn1_elem(tmp, &tmp_size, ID_OCTET, NULL, 0, true);
	return (tmp);
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

int		read_encrypted_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size) {
	int			ret = 1;
	uint8_t		*type;
	uint8_t		*tmp;
	uint64_t	key;
	int			iter = 0;
	uint8_t		salt[8];
	char		*password;
	uint64_t	iv = 0;

	bzero(salt, 8);
	(void)prv;
	tmp = check_rsa_asn1_encrypted_priv_header(asn1, size);
	if (!tmp)
		return (1);
	type = parse_rsa_asn1_encrypted_priv_header(asn1, size, salt, &iter, &iv);
	if (!memcmp(type, DESCBC_OBJECTID, strlen(DESCBC_OBJECTID))) {
		if (get_password_stdin("des-cbc", &password, CMODE_DECRYPT))
			return (1);
		if (get_key_decrypt(NULL, NULL, &key, NULL, salt, NULL, password, iter))
			return (1);
		size_t cipher_size;
		void *ciphertext = get_asn1_elem(tmp, size - (tmp - asn1), ID_OCTET, &cipher_size);
		if (!ciphertext)
			return (1);
		size_t plain_size;
		void *plaintext = des_cbc_decrypt_from_key_iv(ciphertext, cipher_size, key, iv, &plain_size);
		free(ciphertext);
		if (!plaintext)
			return (1);
		ret = read_private_rsa_asn1(prv, plaintext, plain_size);
		free(plaintext);
	}
	else if (!memcmp(type, DESECB_OBJECTID, strlen(DESECB_OBJECTID))) {
		if (get_password_stdin("des-ecb", &password, CMODE_DECRYPT))
			return (1);
		if (get_key_decrypt(NULL, NULL, &key, NULL, salt, NULL, password, iter))
			return (1);
		size_t cipher_size;
		void *ciphertext = get_asn1_elem(tmp, size - (tmp - asn1), ID_OCTET, &cipher_size);
		if (!ciphertext)
			return (1);
		size_t plain_size;
		void *plaintext = des_ecb_decrypt_from_key(ciphertext, cipher_size, key, &plain_size);
		free(ciphertext);
		if (!plaintext)
			return (1);
		ret = read_private_rsa_asn1(prv, plaintext, plain_size);
		free(plaintext);
	}
	return (ret);
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
