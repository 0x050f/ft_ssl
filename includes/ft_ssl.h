#ifndef FT_SSL_H
# define FT_SSL_H

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>

# define PRG_NAME "ft_ssl"

# define NB_FLAGS 4
# define NB_CMDS 2

# define ERR_NB_ARGS		1
# define ERR_INV_OPT		2
# define ERR_INV_ARG		3
# define ERR_OOR_ARG		4 /* OUT OF RANGE */
# define ERR_REQ_ARG		5

# define ERR_MALLOC			6
# define ERR_BADCMD			7

# define CMD_MD5			1
# define CMD_SHA256			2

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
	int				cmd;
	t_lst			*strings;
	t_lst			*files;
	t_options		options;
}					t_ssl;

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
int			ft_strcmp(const char *s1, const char *s2);
void		*ft_memset(void *b, int c, size_t len);

#endif
