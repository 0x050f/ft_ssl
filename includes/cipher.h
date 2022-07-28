#ifndef CIPHER_H
# define CIPHER_H

# define CMODE_ENCODE 0
# define CMODE_DECODE 1

typedef struct		s_options
{
	char			*options;
	int				mode;
	char			*infile;
	char			*outfile;
	char			*key;
	char			*password;
	char			*salt;
	char			*iv;
}					t_options;

/* Cipher functions are located in the cipher/ directory */
char			*hmac_sha256(uint8_t *text, int text_len, uint8_t *key, int key_len, uint8_t *digest);
char			*pbkdf2(char *(prf(uint8_t *, int, uint8_t *, int, uint8_t *)), char *p, uint64_t s, size_t c, size_t dklen);
void			process_cipher(t_ssl *ssl);

/* base64.c */
char			*base64(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* des-ecb.c */
char			*des_ecb(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* des-cbc.c */
char			*des_cbc(uint8_t *str, size_t size, size_t *res_len, t_options *options);

#endif
