#ifndef FT_SSL_H
# define FT_SSL_H

# include <errno.h>
# include <fcntl.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>

# include "hash.h"
# include "error.h"

# define PRG_NAME "ft_ssl"

# define NB_HASH_OPTIONS	4
# define HASH_OPTIONS		{ \
		{"-p", NULL, "pipe STDIN to STDOUT and append the checksum to STDOUT"}, \
		{"-q", NULL, "quiet mode"}, \
		{"-r", NULL, "reverse the format of the output"}, \
		{"-s", "<string>", "print the sum of the given string"} \
}
# define NB_HASH_CMDS		5
# define CMD_HASH			{"md5", "sha256", "sha224", "sha512", "sha384"}
# define FUNC_HASH			{&md5, &sha256, &sha224, &sha512, &sha384}

# define NB_CIPHER_OPTIONS	4
# define NB_CIPHER_DES_OPTIONS	9
# define CIPHER_OPTIONS	{ \
		{"-d", NULL, "decode/decrypt mode"}, \
		{"-e", NULL, "encode/encrypt mode (default)"}, \
		{"-i", "<file>", "input file for message"}, \
		{"-o", "<output>", "output file for message"}, \
		{"-a", NULL, "decode/encode the input/output in base64, depending on the encrypt mode"}, \
		{"-k", "<key>", "key in hex"}, \
		{"-p", "<password>", "password in ascii"}, \
		{"-s", "<salt>", "salt in hex"}, \
		{"-v", "<iv>", "initialization vector in hex"} \
}
# define NB_CIPHER_CMDS		4
# define CMD_CIPHER			{"base64", "des", "des-ecb", "des-cbc"}
# define FUNC_CIPHER		{&base64, &des-cbc, &des-ecb, &des-cbc}

typedef struct		s_options
{
	int				a;
	int				d;
	int				e;
	int				i;
	int				k;
	int				o;
	int				p;
	int				q;
	int				r;
	int				s;
	int				v;
}					t_options;

typedef struct		s_lst
{
	void			*content;
	void			*next;
}					t_lst;

typedef struct		s_ssl
{
	char			*cmd;
	t_lst			*strings;
	t_lst			*files;
	char			*input;
	char			*output;
	char			*key;
	char			*password;
	char			*salt;
	char			*iv;
	t_options		options;
}					t_ssl;

typedef struct		s_cmd_options
{
	int				((*handler)(int, char **, int *, int, t_ssl *, char *));
	int				nb_options;
	char			***options;
}					t_cmd_options;

/* lst.c */
t_lst		*add_list(t_lst **lst, void *content);
void		clear_list(t_lst *lst);

/* args.c */
int			check_args(int argc, char *argv[], t_ssl *ssl);

/* logs.c */
void		show_usage(int fd);
int			args_error(int error, char *str, int range1, int range2);

/* utils.c */
size_t		ft_strlen(const char *s);
char		*ft_strdup(const char *s1);
size_t		ft_strlen_special(char *str, size_t max);
int			ft_strncmp(const char *s1, const char *s2, size_t n);
int			ft_strcmp(const char *s1, const char *s2);
size_t		ft_strcpy(char *dst, const char *src);
void		*ft_memset(void *b, int c, size_t len);
void		*ft_memcpy(void *dst, const void *src, size_t n);
void		ft_toupper(char *str);
int			ishexa(char *str);
int			isprintable(char *str);

#endif
