#ifndef CIPHER_H
# define CIPHER_H

/* Cipher functions are located in the cipher/ directory */
void		process_cipher(t_ssl *ssl);

/* base64.c */
char			*base64(char *str, size_t size);

/* des-ecb.c */
char			*des_ecb(char *str, size_t size);

/* des-cbc.c */
char			*des_cbc(char *str, size_t size);

#endif
