#include "ft_ssl.h"

/*
 * RFC 8018
 * default openssl -pbkdf2:  -iter 10000 -md sha256
*/
char	*pbkdf2(char *password, char *salt, size_t c, size_t dklen)
{
	(void)password;
	(void)salt;
	(void)c;
	(void)dklen;
	/*
	size_t block_len = 0;
	while (block_len < dklen)
	{
		uint64_t u;
	}
	*/
	return (NULL);
}

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

void		print_cipher_result(char *result, size_t result_size, char *cmd, t_options *options)
{
	if (!result_size)
		return ;
	int fd = STDOUT_FILENO;
	if (options->outfile)
	{
		fd = open(options->outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0)
		{
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->outfile, strerror(errno));
			return ;
		}
	}
	if (!strcmp(cmd, "base64"))
	{
		char *tmp = result;
		while (result_size > 64)
		{
			write(fd, tmp, 64);
			write(fd, "\n", 1);
			tmp += 64;
			result_size -= 64;
		}
		write(fd, tmp, result_size);
		write(fd, "\n", 1);
	}
	else
		write(fd, result, result_size);
	if (options->outfile)
		close(fd);
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
	print_cipher_result(result, result_size, cmd, options);
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
	print_cipher_result(result, result_size, cmd, options);
	free(query);
	free(result);
}

int			fill_options(t_options *options, t_ssl *ssl)
{
	options->options = ssl->options;
	/* set options to the last arg recv */
	void *pos_d = strchr(ssl->options, 'd');
	void *pos_e = strchr(ssl->options, 'e');
	options->mode = (pos_e >= pos_d) ? CMODE_ENCODE : CMODE_DECODE;
	options->infile = get_last_content(ssl->opt_args, 'i');
	options->outfile = get_last_content(ssl->opt_args, 'o');
	options->key = get_last_content(ssl->opt_args, 'k');
	if (!options->key && !options->password && strcmp(ssl->cmd, "base64"))
	{
		char msg[256];

		sprintf(msg, "enter %s encryption password: ", ssl->cmd);
		char *tmp = getpass(msg);
		if (!tmp)
		{
			dprintf(STDERR_FILENO, "%s: %s: getpass: %s\n", PRG_NAME, ssl->cmd, strerror(errno));
			return (-1);
		}
		char *password = strdup(tmp);
		if (!password)
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			return (ERR_MALLOC);
		}
		sprintf(msg, "Verifying - enter %s encryption password: ", ssl->cmd);
		tmp = getpass(msg);
		if (!tmp)
		{
			free(password);
			dprintf(STDERR_FILENO, "%s: %s: getpass: %s\n", PRG_NAME, ssl->cmd, strerror(errno));
			return (-1);
		}
		if (strcmp(tmp, password))
		{
			free(password);
			printf("Verify failure\n");
			dprintf(STDERR_FILENO, "bad password read\n");
			return (-2);
		}
		options->password = password;
	}
	else
		options->password = get_last_content(ssl->opt_args, 'p');
	options->salt = get_last_content(ssl->opt_args, 's');
	options->iv = get_last_content(ssl->opt_args, 'v');
	return (0);
}

void	process_cipher(t_ssl *ssl)
{
	size_t			result_len;
	t_options		options;

	(void)result_len;
	memset(&options, 0, sizeof(t_options));
	int ret = fill_options(&options, ssl);
	if (ret)
		return ;
	if (!strchr(ssl->options, 'i'))
		process_cipher_stdin(ssl->cmd, &options);
	else
		process_cipher_file(ssl->cmd, &options);
	free(options.password);
}
