#ifndef STD_H
# define STD_H

# include <stdbool.h>
# include <math.h>

# define CMODE_ENCRYPT 0
# define CMODE_DECRYPT 1

typedef struct		s_options
{
	int				mode;
	bool			text;
	bool			noout;
	bool			modulus;
	bool			check;
	bool			pubin;
	bool			pubout;
	bool			verbose;
	bool			hexdump;
	bool			std_output;
	char			*in;
	char			*out;
	char			*inkey;
	char			*inform;
	char			*outform;
	char			*passin;
	char			*passout;
	char			*cipher;
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

#define		RSA_OBJECTID				"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
#define		DESCBC_OBJECTID				"\x2b\x0e\x03\x02\x07"
#define		DESECB_OBJECTID				"\x2b\x0e\x03\x02\x06"
#define		PBKDF2_OBJECTID				"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"
#define		PBES2_OBJECTID				"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d"
#define		HASHMACSHA256_OBJECTID		"\x2a\x86\x48\x86\xf7\x0d\x02\x09"

#define		INTEGER_0			"\x02\x01\x00"

#define		PUBLIC_EXPONENT		65537

# define HEADER_PRIVATE "-----BEGIN PRIVATE KEY-----\n"
# define FOOTER_PRIVATE "-----END PRIVATE KEY-----"
# define HEADER_ENC_PRIVATE "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
# define FOOTER_ENC_PRIVATE "-----END ENCRYPTED PRIVATE KEY-----"

# define HEADER_PUBLIC "-----BEGIN PUBLIC KEY-----\n"
# define FOOTER_PUBLIC "-----END PUBLIC KEY-----"

/* process.c */
uint64_t			custom_rand(void);
uint64_t			rand_range(uint64_t min, uint64_t max);
uint64_t			power_mod(uint64_t x, uint64_t n, uint64_t p);
unsigned __int128	pgcd_binary(unsigned __int128 a, unsigned __int128 b);
unsigned __int128	inv_mod(unsigned __int128 a, unsigned __int128 n);
bool				check_prime(uint64_t n, double proba, bool verbose);

/* ../cipher/process.c */
int		get_password_stdin(char *cmd, char **password, int mode);

/* ../cipher/base64.c */
char	*base64_decode(unsigned char *str, size_t size, size_t *res_len);
char	*base64_encode(unsigned char *str, size_t size, size_t *res_len);
char	*base64(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* ../cipher/des-ecb.c */
int		get_key_encrypt(uint64_t *key_output, uint8_t *salt_output, char *key, char *salt, uint64_t *iv, char *password, int iter);
int		get_key_decrypt(unsigned char **str, size_t *size, uint64_t *key_output, char *key, uint8_t *salt, uint64_t *iv, char *password, int iter);
char	*des_ecb_encrypt_from_key(uint8_t *str, size_t size, uint64_t key, size_t *res_len);
char	*des_ecb_decrypt_from_key(uint8_t *str, size_t size, uint64_t key, size_t *res_len);

/* ../cipher/des-cbc.c */
char	*des_cbc_encrypt_from_key_iv(uint8_t *str, size_t size, uint64_t key, uint64_t iv, size_t *res_len);
char	*des_cbc_decrypt_from_key_iv(uint8_t *str, size_t size, uint64_t key, uint64_t iv, size_t *res_len);

/* genrsa.c */
char	*genrsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);
char	*generate_base64_public_rsa(unsigned __int128 n, unsigned __int128 e, t_options *options, size_t *res_len);
char	*generate_base64_private_rsa(unsigned __int128 n, unsigned __int128 e, unsigned __int128 d, unsigned __int128 p, unsigned __int128 q, unsigned __int128 dp, unsigned __int128 dq, unsigned __int128 qinv, t_options *options, size_t *res_len);

/* rsa.c */
int		get_rsa_key(struct rsa *rsa, uint8_t *query, size_t size, bool pubin, char *format, char *password);
char	*rsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* rsautl.c */
char	*rsautl(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* asn1.c */
struct asn1		create_asn1_des_cbc(char *payload, size_t size, char *password);
struct asn1		create_asn1_des_ecb(char *payload, size_t size, char *password);
struct asn1		create_asn1_rsa_public_key (unsigned __int128 n, unsigned __int128 e);
struct asn1		create_asn1_rsa_private_key(unsigned __int128 n, unsigned __int128 e, unsigned __int128 d, unsigned __int128 p, unsigned __int128 q, unsigned __int128 dp, unsigned __int128 dq, unsigned __int128 qinv);
int				read_public_rsa_asn1(struct rsa *pub, uint8_t *asn1, size_t size);
int				read_encrypted_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size, char *password);
int				read_private_rsa_asn1(struct rsa *prv, uint8_t *asn1, size_t size);

#endif
