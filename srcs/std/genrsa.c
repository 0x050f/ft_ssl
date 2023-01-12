#include "ft_ssl.h"
#include "std.h"

#define		ID_INTEGER			0x2
#define		ID_OCTET			0x4
#define		ID_NULL				0x5
#define		ID_OBJECT			0x6
#define		ID_SEQ				0x30

#define		PUBLIC_EXPONENT		65537

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

char		*genrsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	char	header[] = "-----BEGIN PRIVATE KEY-----\n";
	char	footer[] = "-----END PRIVATE KEY-----\n";
	char	*result;

	DPRINT("genrsa(\"%.*s\", %zu)\n", (int)size, query, size);

	/* 1. choose two large prime numbers p and q */
	uint64_t p = custom_rand();
	while (!check_prime(p, 1.0))
		p = custom_rand();
	uint64_t q = custom_rand();
	while (!check_prime(q, 1.0))
		q = custom_rand();

//	p = 3732117569;
//	q = 3725659649;

	/* 2. compute n = pq */
	unsigned __int128 n = p * q;
	(void)n;

	/* 3. phi = (p - 1)(q - 1) */
	unsigned __int128 phi = (p - 1) * (q - 1);

	/* 4. coprime phi */
	unsigned __int128 e = PUBLIC_EXPONENT;
	while (pgcd_binary(phi, e) != 1)
		e++;

	/* 5. modular multiplicative inverse */
	/* euclide au + bv = pgcd(a, b) | ed ≡ (1 mod phi)*/
	unsigned __int128 d = inv_mod(e, phi);

	printf("modulus (n): %llu\n", n);
	printf("publicExponent (e): %llu\n", e);
	printf("privateExponent (d): %llu\n", d);
	printf("prime1 (p): %llu\n", p);
	printf("prime2 (q): %llu\n", q);

	unsigned __int128 dp = d % (p - 1);
	unsigned __int128 dq = d % (q - 1);
	unsigned __int128 qinv = inv_mod(q, p);

	printf("exponent1 (dp): %llu\n", d % (p - 1));
	printf("exponent2 (dq): %llu\n", d % (q - 1));
	printf("coefficient (qinv): %llu\n", inv_mod(q, p));

	uint8_t		to_encode[4096];
	uint8_t		*ptr = to_encode;

	memset(to_encode, 0, 4096);

	// MASTER SEQUENCE
	*ptr++ = ID_SEQ;
	uint8_t		*size_asn = ptr++;

	ptr += add_integer_asn1(ptr, 0);

	// SEQUENCE OBJECT
	*ptr++ = ID_SEQ;
	*ptr++ = 0x0d;
	
	*ptr++ = ID_OBJECT;
	*ptr++ = 0x09;

	memcpy(ptr, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 0x09);
	ptr += 0x09;

	*ptr++ = ID_NULL;
	*ptr++ = 0x0;

	// OCTET STRING + SEQUENCE
	*ptr++ = ID_OCTET;
	uint8_t		*size_octet = ptr++;
	*ptr++ = ID_SEQ;
	ptr++;
	size_t		size_seq = 0;

	size_seq += add_integer_asn1(ptr + size_seq, 0);
	size_seq += add_integer_asn1(ptr + size_seq, n);
	size_seq += add_integer_asn1(ptr + size_seq, e);
	size_seq += add_integer_asn1(ptr + size_seq, d);
	size_seq += add_integer_asn1(ptr + size_seq, p);
	size_seq += add_integer_asn1(ptr + size_seq, q);
	size_seq += add_integer_asn1(ptr + size_seq, dp);
	size_seq += add_integer_asn1(ptr + size_seq, dq);
	size_seq += add_integer_asn1(ptr + size_seq, qinv);
	*(ptr - 1) = size_seq;
	*size_octet = size_seq + 2;
	ptr += size_seq;
	*size_asn = (ptr - to_encode) - 2;

	size_t	len_encoded;
	char	*encoded = base64_encode(to_encode, *size_asn + 2, &len_encoded);

//	printf("phi: %llu\n", phi);

	printf("done !\n");

	*res_len = strlen(header) + strlen(footer) + len_encoded + ceil((double)len_encoded / 64.0) + 1;
	result = malloc(*res_len);
	memset(result, 0, *res_len);

	ptr = (uint8_t *)result;

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
	(void)query;
	(void)size;
	(void)res_len;
	(void)options;
	return (result);
}
