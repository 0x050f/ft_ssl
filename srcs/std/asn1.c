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
	size_t		i;
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

	// TODO: CHANGE
	tmp = inv_nb(n);
	append_asn1_elem(&asn1, ID_INTEGER, &tmp, get_size_in_byte(n));
	tmp = inv_nb(e);
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
	char					*password;
	unsigned __int128		tmp;
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
	tmp = inv_nb(iv);
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
	tmp = inv_nb(iter);
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
	uint8_t					salt[8];
	uint64_t				key;
	char					*password;
	unsigned __int128		tmp;
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
	tmp = inv_nb(iter);
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

uint8_t		*check_elem(uint8_t *asn1, size_t size, uint8_t elem, uint8_t *value) {
	int		size = 0;
	int		i = 0;

	if (size < 2)
		return (NULL);
	if (asn1[i++] != elem)
		return (NULL);
	if (asn1[i] & 0x80)
		i += (asn1[i] ^ 0x80) + 1;
	else
		i++;
	if (size <= i)
		return (NULL);
	if (value) {
		
	}
	return (&asn1[i]);
}

uint8_t		*check_rsa_asn1_encrypted_priv_header(uint8_t *asn1, size_t size) {
	uint8_t		*tmp;

	tmp = check_elem(asn1, size, ID_SEQ);
	if (!tmp)
		return (NULL);
	size -= tmp - asn1;
	asn1 = tmp;

	tmp = check_elem(asn1, size, ID_SEQ);
	if (!tmp)
		return (NULL);
	size -= tmp - asn1;
	asn1 = tmp;

	if (asn1[i++] != ID_SEQ)
		return (NULL);
	if (asn1[i] & 0x80)
		i += (asn1[i] ^ 0x80) + 1;
	else
		i++;
	if (asn1[i++] != ID_OBJECT)
		return (NULL);
	if (!memcmp(&asn1[i], PBES2_OBJECTID, strlen(PBES2_OBJECTID)))
		return (NULL);
	i += strlen(PBES2_OBJECTID);
	if (asn1[i++] != ID_SEQ)
		return (NULL);
	if (asn1[i] & 0x80)
		i += (asn1[i] ^ 0x80) + 1
	else
		i++;
	if (asn1[i++] != ID_SEQ)
		return (NULL);
	if (asn1[i] & 0x80)
		i += (asn1[i] ^ 0x80) + 1
	else
		i++;
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

int		read_private_encrypted_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size) {
	uint8_t *tmp;

	tmp = check_rsa_asn1_encrypted_priv_header(asn1, size);
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
