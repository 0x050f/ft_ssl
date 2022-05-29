#ifndef FT_SSL_H
# define FT_SSL_H

# include <errno.h>
# include <fcntl.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>

# define PRG_NAME "ft_ssl"

#ifdef DEBUG
	#define DPRINT(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, \
		__FILE__, __LINE__, __func__, ##args)
#else
	#define DPRINT(fmt, args...)
#endif

#define PRINT_BITS(x, y) uint8_t *bytes = (uint8_t *)&x; for(int i = (y / 8) - 1; i >= 0; i--){printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(bytes[i]));}printf("\n");
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

/*
	OPTIONS:
	{name, argument, desc, check}
	'f' option set for file
*/

# define NB_COLUMNS_OPTIONS	4

# define NB_HASH_OPTIONS	4
# define HASH_OPTIONS		{ \
		{"-p", NULL, "pipe STDIN to STDOUT and append the checksum to STDOUT", NULL}, \
		{"-q", NULL, "quiet mode", NULL}, \
		{"-r", NULL, "reverse the format of the output", NULL}, \
		{"-s", "<string>", "print the sum of the given string", NULL} \
}
# define NB_HASH_CMDS		5
# define CMD_HASH			{"md5", "sha256", "sha224", "sha512", "sha384"}
# define FUNC_HASH			{&md5, &sha256, &sha224, &sha512, &sha384}

# define NB_CIPHER_OPTIONS	4
# define NB_CIPHER_DES_OPTIONS	9
# define CIPHER_OPTIONS	{ \
		{"-d", NULL, "decode/decrypt mode", NULL}, \
		{"-e", NULL, "encode/encrypt mode (default)", NULL}, \
		{"-i", "<file>", "input file for message", NULL}, \
		{"-o", "<output>", "output file for message", NULL}, \
		{"-a", NULL, "decode/encode the input/output in base64, depending on the encrypt mode", NULL}, \
		{"-k", "<key>", "key in hex", "HEX"}, \
		{"-p", "<password>", "password in ascii", "PRINT"}, \
		{"-s", "<salt>", "salt in hex", "HEX"}, \
		{"-v", "<iv>", "initialization vector in hex", "HEX"} \
}
# define NB_CIPHER_CMDS		4
# define CMD_CIPHER			{"base64", "des", "des-ecb", "des-cbc"}
# define FUNC_CIPHER		{&base64, &des_cbc, &des_ecb, &des_cbc}

# define MODE_HASH			1
# define MODE_CIPHER		2

typedef struct		s_opt_arg
{
	char			arg;
	void			*content;
	void			*next;
}					t_opt_arg;

typedef struct		s_ssl
{
	char			*cmd;
	int				mode;
	t_opt_arg		*opt_args;
	char			options[32];
}					t_ssl;

typedef struct		s_cmd_options
{
	int				nb_options;
	char			***options;
}					t_cmd_options;

# include "hash.h"
# include "cipher.h"
# include "error.h"

/* opt_arg.c */
t_opt_arg	*append_opt_arg(t_opt_arg **opt_args, char arg, void *content);
void		clear_opt_arg(t_opt_arg *opt_args);
t_opt_arg	*get_last_arg(t_opt_arg *opt_args, char arg);
void		*get_last_content(t_opt_arg *opt_args, char arg);

/* args.c */
int			check_args(int argc, char *argv[], t_ssl *ssl);

/* logs.c */
void		show_usage(int fd);
int			args_error(int error, char *str, int range1, int range2);

/* utils.c */
int			ceil(float num);
size_t		ft_strlen_special(char *str, size_t max);
void		ft_toupper(char *str);
int			ishexa(char *str);
int			isprintable(char *str);
char		*read_query(int fd, size_t *size);

#endif
