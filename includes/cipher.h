#include <stdbool.h>

#ifndef CIPHER_H
# define CIPHER_H

# define CMODE_ENCODE 0
# define CMODE_DECODE 1

typedef struct		s_options
{
	int				mode;
	bool			base64;
	char			*infile;
	char			*outfile;
	char			*key;
	char			*password;
	char			*salt;
	char			*iv;
	int				iter;
}					t_options;

/* Cipher functions are located in the cipher/ directory */
uint8_t			*hmac_sha256(uint8_t *text, int text_len, uint8_t *key, int key_len);
uint8_t			*pbkdf2(uint8_t *(prf(uint8_t *, int, uint8_t *, int)), char *p, size_t psize, char *s, size_t ssize, size_t c, size_t dklen);

/* base64.c */
char			*base64_decode(unsigned char *str, size_t size, size_t *res_len);
char			*base64_encode(unsigned char *str, size_t size, size_t *res_len);
char			*base64(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* des-ecb.c */
char			*des_ecb(uint8_t *str, size_t size, size_t *res_len, t_options *options);
uint64_t		permutation(uint64_t block, size_t size_input, uint8_t *table, size_t size_output);
uint32_t		substitution(uint64_t block);
uint32_t		feistel_function(uint32_t half_block, uint64_t key);
void			get_salt(uint8_t dest[8], char *salt);
int				get_key_encrypt(uint64_t *key_output, uint8_t *salt_output, char *key, char *salt, uint64_t *iv, char *password, int iter);
int				get_key_decrypt(unsigned char **str, size_t *size, uint64_t *key_output, char *key, uint8_t *salt, uint64_t *iv, char *password, int iter);

/* des-cbc.c */
char			*des_cbc(uint8_t *str, size_t size, size_t *res_len, t_options *options);

#endif
