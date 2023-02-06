#include "ft_ssl.h"
#include "std.h"

char		*generate_base64_public_rsa(
	unsigned __int128	n,
	unsigned __int128	e,
	t_options			*options,
	size_t				*res_len
) {
	(void)options;
	char header[] = HEADER_PUBLIC;
	char footer[] = FOOTER_PUBLIC;
	char *result;

	struct asn1 rsa_asn1 = create_asn1_rsa_public_key(n, e);
	if (!rsa_asn1.content) {
		return (NULL);
	}
	size_t	len_encoded;
	char	*encoded = base64_encode(rsa_asn1.content, rsa_asn1.length, &len_encoded);

	free(rsa_asn1.content);
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

char		*generate_base64_private_rsa(
	unsigned __int128	n,
	unsigned __int128	e,
	unsigned __int128	d,
	unsigned __int128	p,
	unsigned __int128	q,
	unsigned __int128	dp,
	unsigned __int128	dq,
	unsigned __int128	qinv,
	t_options			*options,
	size_t				*res_len
) {
	(void)options;
	char	*header;
	char	*footer;
	char	header_private[] = HEADER_PRIVATE;
	char	footer_private[] = FOOTER_PRIVATE;
	char	header_enc_priv[] = HEADER_ENC_PRIVATE;
	char	footer_enc_priv[] = FOOTER_ENC_PRIVATE;
	char	*result;

	header = (char *)header_private;
	footer = (char *)footer_private;

	struct asn1 rsa_asn1 = create_asn1_rsa_private_key(n, e, d, p, q, dp, dq, qinv);
	if (!rsa_asn1.content) {
		return (NULL);
	}

	if (options->cipher) {
		struct asn1 cipher_asn1;

		bzero(&cipher_asn1, sizeof(struct asn1));
		if (!strcmp(options->cipher, "des-ecb"))
			cipher_asn1 = create_asn1_des_ecb((char *)rsa_asn1.content, rsa_asn1.length, options->passout);
		else if (!strcmp(options->cipher, "des-cbc") || !strcmp(options->cipher, "des"))
			cipher_asn1 = create_asn1_des_cbc((char *)rsa_asn1.content, rsa_asn1.length, options->passout);
		free(rsa_asn1.content);
		rsa_asn1 = cipher_asn1;
		header = (char *)header_enc_priv;
		footer = (char *)footer_enc_priv;
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

char		*genrsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {

	DPRINT("genrsa(\"%.*s\", %zu)\n", (int)size, query, size);

	// Unused variable but important for std fn format
	(void)query;
	(void)size;

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

	return (generate_base64_private_rsa(n, e, d, p, q, dp, dq, qinv, options, res_len));
}
