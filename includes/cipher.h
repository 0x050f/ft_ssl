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
char			*pbkdf2(char *p, uint64_t s, size_t c, size_t dklen);
void			process_cipher(t_ssl *ssl);

/* base64.c */
char			*base64(unsigned char *str, size_t size, size_t *res_len, t_options *options);

/* des-ecb.c */
char			*des_ecb(unsigned char *str, size_t size, size_t *res_len, t_options *options);

/* des-cbc.c */
char			*des_cbc(unsigned char *str, size_t size, size_t *res_len, t_options *options);

#endif
