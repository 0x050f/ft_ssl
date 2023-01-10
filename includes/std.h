#ifndef STD_H
# define STD_H

# include <stdbool.h>

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

/* ../cipher/base64.c */
char	*base64(uint8_t *str, size_t size, size_t *res_len, t_options *options);

/* genrsa.c */
char	*genrsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* rsa.c */
char	*rsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* rsautl.c */
char	*rsautl(unsigned char *query, size_t size, size_t *res_len, t_options *options);

#endif
