#ifndef FT_SSL_H
# define FT_SSL_H

# define _GNU_SOURCE

# include <errno.h>
# include <fcntl.h>
# include <math.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <sys/stat.h>
# include <time.h>
# include <unistd.h>

# define PRG_NAME "ft_ssl"

#ifdef DEBUG
	#define DPRINT(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, \
		__FILE__, __LINE__, __func__, ##args)
#else
	#define DPRINT(fmt, args...)
#endif

# define PRINT_BITS(x, y) uint8_t *BYTES(x,__LINE__) = (uint8_t *)&x; for(int i = (y / 8) - 1; i >= 0; i--){printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(BYTES(x,__LINE__)[i]));}printf("\n");
# define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
# define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')
# define BYTES(X,Y) COMBINE(X,Y)
# define COMBINE(X,Y) X##Y  // helper macro

/*
	OPTIONS:
	{name, fullname, argument, desc, check}
	'f' option set for file
*/

# define PADDING_ARG	20
# define PADDING_DESC	35

# define NB_COLUMNS_OPTIONS	5

# define INDEX_NAME			0
# define INDEX_FULLNAME		1
# define INDEX_ARG			2
# define INDEX_DESC			3
# define INDEX_CHECK		4

# define NB_HASH_OPTIONS	4
# define HASH_OPTIONS		{ \
	{"-p", "--pipe", NULL, "pipe STDIN to STDOUT and append the checksum to STDOUT", NULL}, \
	{"-q", "--quiet", NULL, "quiet mode", NULL}, \
	{"-r", "--reverse", NULL, "reverse the format of the output", NULL}, \
	{"-s", "--string", "<string>", "print the sum of the given string", NULL} \
}

# define NB_HASH_CMDS		5
# define CMD_HASH	{ \
	{"md5", "p,q,r,s"}, \
	{"sha256", "p,q,r,s"}, \
	{"sha224", "p,q,r,s"}, \
	{"sha512", "p,q,r,s"}, \
	{"sha384", "p,q,r,s"} \
}
# define FUNC_HASH			{&md5, &sha256, &sha224, &sha512, &sha384}

# define NB_CIPHER_OPTIONS	10
# define CIPHER_OPTIONS		{ \
	{"-d", "--decode", NULL, "decode/decrypt mode", NULL}, \
	{"-e", "--encode", NULL, "encode/encrypt mode (default)", NULL}, \
	{"-i", "--input", "<file>", "input file for message", NULL}, \
	{"-o", "--output", "<file>", "output file for message", NULL}, \
	{"-a", "--base64", NULL, "decode/encode the input/output in base64, depending on the encrypt mode", NULL}, \
	{"-k", "--key", "<key>", "key in hex", "HEX"}, \
	{"-p", "--password", "<password>", "password in ascii", "PRINT"}, \
	{"-s", "--salt", "<salt>", "salt in hex", "HEX"}, \
	{"-v", "--iv", "<iv>", "initialization vector in hex", "HEX"}, \
	{"-t", "--iter", "<iter>", "number of iteration of pbkdf2 (default: 10000)", "INT"} \
}
# define NB_CIPHER_CMDS		4
# define CMD_CIPHER		{ \
	{"base64", "d,e,i,o"}, \
	{"des", "d,e,i,o,a,k,p,s,v,t"}, \
	{"des-ecb", "d,e,i,o,a,k,p,s,v,t"}, \
	{"des-cbc", "d,e,i,o,a,k,p,s,v,t"} \
}
# define FUNC_CIPHER		{&base64, &des_cbc, &des_ecb, &des_cbc}

# define NB_STD_OPTIONS		21
# define STD_OPTIONS		{ \
	{"-v", "-verbose", NULL, "verbose output", NULL}, \
	{"-i", NULL, NULL, "print in the standard output"}, \
	{NULL, "-in", "<file>", "input file", NULL}, \
	{"-o", "-out", "<output>", "output file", NULL}, \
	{NULL, "-inkey", "<file>", "input file", NULL}, \
	{NULL, "-inform", "DER|PEM", "input format", NULL}, \
	{NULL, "-outform", "DER|PEM", "output format", NULL}, \
	{NULL, "-passin", "<arg>", "input file pass phrase source", NULL}, \
	{NULL, "-passout", "<arg>", "output file pass phrase source", NULL}, \
	{NULL, "-text", NULL, "print the key in text", NULL}, \
	{NULL, "-noout", NULL, "don't print key out", NULL}, \
	{NULL, "-modulus", NULL, "print the RSA key modulus", NULL}, \
	{NULL, "-check", NULL, "verify key consistency", NULL}, \
	{NULL, "-pubin", NULL, "expect a public key in input file", NULL}, \
	{NULL, "-pubout", NULL, "output a public key", NULL}, \
	{NULL, "-encrypt", NULL, "encrypt with public key", NULL}, \
	{NULL, "-decrypt", NULL, "decrypt with private key", NULL}, \
	{NULL, "-hexdump", NULL, "hex dump output", NULL}, \
	{NULL, "-des", NULL, "encrypt the private key with the specifed cipher", NULL}, \
	{NULL, "-des-ecb", NULL, "encrypt the private key with the specifed cipher", NULL}, \
	{NULL, "-des-cbc", NULL, "encrypt the private key with the specifed cipher", NULL} \
}
# define NB_STD_CMDS		3
# define CMD_STD		{ \
	{"genrsa", "i,o,passout,des,des-ecb,des-cbc"}, \
	{"rsa", "in,out,inform,outform,passin,passout,text,noout,modulus,check,pubin,pubout,des,des-ecb,des-cbc"}, \
	{"rsautl", "in,out,inkey,pubin,decrypt,encrypt,hexdump"} \
}
# define FUNC_STD		{&genrsa, &rsa, &rsautl}

# define MODE_HASH			1
# define MODE_CIPHER		2
# define MODE_STD			3

typedef struct		s_opt_arg
{
	int				index;
	char			*arg;
	void			*content;
	void			*next;
}					t_opt_arg;

typedef struct		s_ssl
{
	char			*cmd;
	int				mode;
	t_opt_arg		*opt_args;
}					t_ssl;

typedef struct		s_cmd_options
{
	int				nb_options;
	char			***options;
}					t_cmd_options;

# include "error.h"

/* opt_arg.c */
t_opt_arg	*append_opt_arg(t_opt_arg **opt_args, char *arg, void *content);
void		clear_opt_arg(t_opt_arg *opt_args);
t_opt_arg	*get_last_arg(t_opt_arg *opt_args, char *arg);
void		*get_last_content(t_opt_arg *opt_args, char *arg);

/* args.c */
int			check_args(int argc, char *argv[], t_ssl *ssl);

/* logs.c */
void		show_cmd(int fd, char *cmd, t_cmd_options *cmd_options);
void		show_usage(int fd);
int			args_error(int error, char *str, int range1, int range2);

/* utils.c */
char		*add_padding_str(char *str, size_t size_line, char *padd_str);
char		*bytes2hex(uint8_t *bytes, size_t size);
void		hex2bytes(uint8_t *result, size_t size, const char *hex);
uint64_t	hex2int64(const char *hex);
uint32_t	hex2int32(const char *hex);
void		*b_memcpy(void *dest, const void *src, size_t n);
size_t		ft_strlen_special(char *str, size_t max);
void		ft_toupper(char *str);
int			isint(char *str);
int			ishexa(char *str);
int			isprintable(char *str);
char		*read_query(int fd, size_t *size);
char		*first_nonchar(char *str, char c);

/* process.c */
int			process_cipher(t_ssl *ssl);
int			process_hash(t_ssl *ssl);
int			process_std(t_ssl *ssl);

#endif
