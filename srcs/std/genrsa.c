#include "ft_ssl.h"
#include "std.h"

#define		ID_INTEGER			0x2
#define		ID_OCTET			0x4
#define		ID_NULL				0x5
#define		ID_OBJECT			0x6
#define		ID_SEQ				0x30

#define		RSA_OBJECTID		"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

#define		PUBLIC_EXPONENT		65537

struct asn1 {
	size_t		length;
	uint8_t		*content;
};

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
	tmp[i++] = strlen(RSA_OBJECTID) + 2;

	tmp[i++] = ID_OBJECT;
	tmp[i++] = strlen(RSA_OBJECTID);

	memcpy(tmp + i, RSA_OBJECTID, strlen(RSA_OBJECTID));
	i += strlen(RSA_OBJECTID);

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

char		*genrsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	char	header[] = "-----BEGIN PRIVATE KEY-----\n";
	char	footer[] = "-----END PRIVATE KEY-----\n";
	char	*result;

	DPRINT("genrsa(\"%.*s\", %zu)\n", (int)size, query, size);

	(void)query;
	(void)size;
	(void)res_len;
	(void)options;

	/* 1. choose two large prime numbers p and q */
	uint64_t p = custom_rand();
	while (!check_prime(p, 1.0))
		p = custom_rand();
	uint64_t q = custom_rand();
	while (!check_prime(q, 1.0))
		q = custom_rand();

	/* 2. compute n = pq */
	unsigned __int128 n = (unsigned __int128)p * q;

	/* 3. phi = (p - 1)(q - 1) */
	unsigned __int128 phi = ((unsigned __int128)p - 1) * (q - 1);

	/* 4. coprime phi */
	unsigned __int128 e = PUBLIC_EXPONENT;
	while (pgcd_binary(phi, e) != 1)
		e++;

	/* 5. modular multiplicative inverse */
	/* euclide au + bv = pgcd(a, b) | ed ≡ (1 mod phi)*/
	unsigned __int128 d = inv_mod(e, phi);

	unsigned __int128 dp = d % (p - 1);
	unsigned __int128 dq = d % (q - 1);
	unsigned __int128 qinv = inv_mod(q, p);

	struct asn1 rsa_asn1 = create_asn1_rsa_private_key(n, e, d, p, q, dp, dq, qinv);
	if (!rsa_asn1.content) {
		return (NULL);
	}

	size_t	len_encoded;
	char	*encoded = base64_encode(rsa_asn1.content, rsa_asn1.length, &len_encoded);

	free(rsa_asn1.content);

	// ceil used to provide newlines every 64 base64 char
	*res_len = strlen(header) + strlen(footer) + len_encoded + ceil((double)len_encoded / 64.0) + 1;
	result = malloc(*res_len);
	if (!result)
		return (NULL);
	memset(result, 0, *res_len);

	uint8_t	*ptr = (uint8_t *)result;

	memcpy(ptr, header, strlen(header));
	ptr += strlen(header);
	memcpy(ptr, encoded, len_encoded);
	size_t i = len_encoded;
	while (i) {
		size_t len_copy = (i > 64) ? 64 : i;
		memcpy(ptr, encoded + len_encoded - i, len_copy);
		ptr += len_copy;
		memcpy(ptr, "\n", 1);
		ptr += 1;
		i -= len_copy;
	}
	memcpy(ptr, footer, strlen(footer));
	free(encoded);
	return (result);
}
