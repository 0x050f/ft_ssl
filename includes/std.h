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

/* rsa.c */
char	*rsa(unsigned char *query, size_t size, size_t *res_len, t_options *options);

/* rsautl.c */
char	*rsautl(unsigned char *query, size_t size, size_t *res_len, t_options *options);

#endif
