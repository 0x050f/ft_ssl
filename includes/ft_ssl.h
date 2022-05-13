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

# define ERR_NB_ARGS		1
# define ERR_INV_OPT		2
# define ERR_INV_ARG		3
# define ERR_OOR_ARG		4 /* OUT OF RANGE */
# define ERR_REQ_ARG		5

# define ERR_MALLOC			6
# define ERR_BADCMD			7

# define NB_FLAGS 4
# define NB_CMDS 5
# define CMD_HASHES			{"md5", "sha256", "sha224", "sha512", "sha384"}
# define CMD_FUNC			{&md5, &sha256, &sha224, &sha512, &sha384}

typedef struct		s_options
{
	int				p;
	int				q;
	int				r;
	int				s;
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
	t_options		options;
}					t_ssl;

/* sha384.c */
char		*sha384(char *str, size_t size);

/* sha512.c */
char		*sha512(char *str, size_t size);

/* sha224.c */
char		*sha224(char *str, size_t size);

/* sha256.c */
char		*sha256(char *str, size_t size);

/* md5.c */
char		*md5(char *str, size_t size);

/* lst.c */
t_lst		*add_list(t_lst **lst, void *content);
void		clear_list(t_lst *lst);

/* args.c */
int			check_args(int argc, char *argv[], t_ssl *ssl);

/* logs.c */
void		show_commands(int fd);
void		show_options(int fd);
void		show_usage(int fd);
int			args_error(int error, char *str, int range1, int range2);

/* utils.c */
size_t		ft_strlen(const char *s);
size_t		ft_strlen_special(char *str, size_t max);
int			ft_strcmp(const char *s1, const char *s2);
size_t		ft_strcpy(char *dst, const char *src);
void		*ft_memset(void *b, int c, size_t len);
void		*ft_memcpy(void *dst, const void *src, size_t n);
void		ft_toupper(char *str);

#endif
