#include "ft_ssl.h"

char		*launch_cipher(char *cmd, char *query, size_t size, size_t *res_len, t_options *options)
{
	char *cmds[NB_CIPHER_CMDS] = CMD_CIPHER;
	char *(*functions[NB_CIPHER_CMDS])(unsigned char *, size_t, size_t *, t_options *) = FUNC_CIPHER;

	for (int i = 0; i < NB_CIPHER_CMDS; i++)
	{
		if (!strcmp(cmd, cmds[i]))
			return (functions[i]((unsigned char *)query, size, res_len, options));
	}
	return (NULL);
}

void		process_cipher_file(char *cmd, t_options *options)
{
	size_t		size;
	char		*query;
	char		*result;
	size_t		result_size;

	int fd = open(options->infile, O_RDONLY);
	if (fd < 0)
	{
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->infile, strerror(errno));
		return ;
	}
	if (!(query = read_query(fd, &size)))
	{
		close(fd);
		return ;
	}
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		return ;
	}
	char *tmp = result;
	while (result_size > 64)
	{
		write(STDOUT_FILENO, tmp, 64);
		write(STDOUT_FILENO, "\n", 1);
		tmp += 64;
		result_size -= 64;
	}
	write(STDOUT_FILENO, tmp, result_size);
	write(STDOUT_FILENO, "\n", 1);
	free(query);
	free(result);
	close(fd);
}

void		process_cipher_stdin(char *cmd, t_options *options)
{
	size_t	size;
	char	*query;
	char	*result;
	size_t	result_size;

	if (!(query = read_query(STDIN_FILENO, &size)))
		return ;
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		return ;
	}
	char *tmp = result;
	while (result_size > 64)
	{
		write(STDOUT_FILENO, tmp, 64);
		write(STDOUT_FILENO, "\n", 1);
		tmp += 64;
		result_size -= 64;
	}
	write(STDOUT_FILENO, tmp, result_size);
	write(STDOUT_FILENO, "\n", 1);
	free(query);
	free(result);
}

void	fill_options(t_options *options, t_ssl *ssl)
{
	options->options = ssl->options;
	/* set options to the last arg recv */
	void *pos_d = strchr(ssl->options, 'd');
	void *pos_e = strchr(ssl->options, 'e');
	options->mode = (pos_e >= pos_d) ? CMODE_ENCODE : CMODE_DECODE;
	options->infile = get_last_content(ssl->opt_args, 'i');
	options->outfile = get_last_content(ssl->opt_args, 'o');
	options->key = get_last_content(ssl->opt_args, 'k');
	options->password = get_last_content(ssl->opt_args, 'p');
	options->salt = get_last_content(ssl->opt_args, 's');
	options->iv = get_last_content(ssl->opt_args, 'v');
}

void	process_cipher(t_ssl *ssl)
{
	size_t			result_len;
	t_options		options;

	(void)result_len;
	memset(&options, 0, sizeof(t_options));
	fill_options(&options, ssl);
	if (!strchr(ssl->options, 'i'))
		process_cipher_stdin(ssl->cmd, &options);
	else
		process_cipher_file(ssl->cmd, &options);
//	char *str = launch_cipher(ssl, "bonjour", strlen("bonjour"), &result_len, options);
//	printf("%s\n", str);
//	free(str);
}
