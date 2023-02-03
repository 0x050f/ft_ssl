#ifndef STD_H
# define STD_H

# include <stdbool.h>
# include <math.h>

# define CMODE_ENCRYPT 0
# define CMODE_DECRYPT 1

typedef struct		s_options
{
	int				mode;
	bool			des;
	bool			text;
	bool			noout;
	bool			modulus;
	bool			check;
	bool			pubin;
	bool			pubout;
	bool			hexdump;
	bool			std_output;
	char			*in;
	char			*out;
	char			*inkey;
	char			*inform;
	char			*outform;
	char			*passin;
	char			*passout;
}					t_options;

struct asn1 {
	size_t		length;
	uint8_t		*content;
};

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

#define		ID_INTEGER			0x2
#define		ID_BIT				0x3
#define		ID_OCTET			0x4
#define		ID_NULL				0x5
#define		ID_OBJECT			0x6
#define		ID_SEQ				0x30

#define		RSA_OBJECTID		"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
#define		INTEGER_0			"\x02\x01\x00"

#define		PUBLIC_EXPONENT		65537

# define HEADER_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
# define FOOTER_PRIVATE "-----END PRIVATE KEY-----"

# define HEADER_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
# define FOOTER_PUBLIC "-----END PUBLIC KEY-----"

/* process.c */
uint64_t			custom_rand(void);
uint64_t			rand_range(uint64_t min, uint64_t max);
uint64_t			power_mod(uint64_t x, uint64_t n, uint64_t p);
unsigned __int128	pgcd_binary(unsigned __int128 a, unsigned __int128 b);
unsigned __int128	inv_mod(unsigned __int128 a, unsigned __int128 n);
bool				check_prime(uint64_t n, double proba);

/* ../cipher/base64.c */
char	*base64_decode(unsigned char *str, size_t size, size_t *res_len);
char	*base64_encode(unsigned char *str, size_t size, size_t *res_len);
char	*base64(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* genrsa.c */
char	*genrsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);
char	*generate_base64_public_rsa(unsigned __int128 n, unsigned __int128 e, size_t *res_len);
char	*generate_base64_private_rsa(unsigned __int128 n, unsigned __int128 e, unsigned __int128 d, unsigned __int128 p, unsigned __int128 q, unsigned __int128 dp, unsigned __int128 dq, unsigned __int128 qinv, size_t *res_len);

/* rsa.c */
char	*rsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* rsautl.c */
char	*rsautl(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* asn1.c */
struct asn1		create_asn1_rsa_public_key (unsigned __int128 n, unsigned __int128 e);
struct asn1		create_asn1_rsa_private_key(unsigned __int128 n, unsigned __int128 e, unsigned __int128 d, unsigned __int128 p, unsigned __int128 q, unsigned __int128 dp, unsigned __int128 dq, unsigned __int128 qinv);
int				read_public_rsa_asn1(struct rsa *pub, uint8_t *asn1, size_t size);
int				read_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size);

#endif
