#include "ft_ssl.h"

char		*read_query(int fd, size_t *size)
{
	char	*query;
	char	*tmp;
	size_t	ret;
	char	buffer[4096];

	*size = 0;
	query = malloc(0);
	if (!query)
	{
		dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
		return (NULL);
	}
	while ((ret = read(fd, buffer, 4096)))
	{
		tmp = malloc(sizeof(char) * *size + ret);
		if (!tmp)
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			free(query);
			return (NULL);
		}
		if (query)
			ft_memcpy(tmp, query, *size);
		ft_memcpy(tmp + *size, buffer, ret);
		free(query);
		*size += ret;
		query = tmp;
	}
	return (query);
}

void		process_files(t_ssl *ssl)
{
	t_lst	*tmp;
	size_t	size;
	char	*query;
	char	*result;

	tmp = ssl->files;
	while (tmp)
	{
		int fd = open(tmp->content, O_RDONLY);
		if (fd < 0)
		{
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, ssl->cmd, (char *)tmp->content, strerror(errno));
			tmp = tmp->next;
			continue;
		}
		if (!(query = read_query(fd, &size)))
		{
			close(fd);
			return ;
		}
		if (!ft_strcmp(ssl->cmd, CMD_MD5))
			result = md5(query, size);
		else if (!ft_strcmp(ssl->cmd, CMD_SHA256))
			result = sha256(query, size);
		else if (!ft_strcmp(ssl->cmd, CMD_SHA512))
			result = sha512(query, size);
		else if (!ft_strcmp(ssl->cmd, CMD_SHA384))
			result = sha384(query, size);
		if (!result)
			return ;
		if (!ssl->options.q && !ssl->options.r)
		{
			char uppercase[12];

			strcpy(uppercase, ssl->cmd);
			ft_toupper(uppercase);
			printf("%s(%s) = ", uppercase, tmp->content);
		}
		printf("%s", result);
		if (!ssl->options.q && ssl->options.r)
			printf(" %s", tmp->content);
		printf("\n");
		free(query);
		free(result);
		close(fd);
		tmp = tmp->next;
	}
}

void		process_strings(t_ssl *ssl)
{
	t_lst	*tmp;
	char	*result;

	tmp = ssl->strings;
	while (tmp)
	{
		if (!ft_strcmp(ssl->cmd, CMD_MD5))
			result = md5(tmp->content, ft_strlen(tmp->content));
		else if (!ft_strcmp(ssl->cmd, CMD_SHA256))
			result = sha256(tmp->content, ft_strlen(tmp->content));
		else if (!ft_strcmp(ssl->cmd, CMD_SHA512))
			result = sha512(tmp->content, ft_strlen(tmp->content));
		else if (!ft_strcmp(ssl->cmd, CMD_SHA384))
			result = sha384(tmp->content, ft_strlen(tmp->content));
		if (!result)
			return ;
		if (!ssl->options.q && !ssl->options.r)
		{
			char uppercase[12];

			strcpy(uppercase, ssl->cmd);
			ft_toupper(uppercase);
			printf("%s(\"%s\") = ", uppercase, tmp->content);
		}
		printf("%s", result);
		if (!ssl->options.q && ssl->options.r)
			printf(" \"%s\"", tmp->content);
		printf("\n");
		free(result);
		tmp = tmp->next;
	}
}

void		process_stdin(t_ssl *ssl)
{
	size_t	size;
	char	*query;
	char	*result;

	if (!(query = read_query(STDIN_FILENO, &size)))
		return ;
	if (!ft_strcmp(ssl->cmd, CMD_MD5))
		result = md5(query, size);
	else if (!ft_strcmp(ssl->cmd, CMD_SHA256))
		result = sha256(query, size);
	else if (!ft_strcmp(ssl->cmd, CMD_SHA512))
		result = sha512(query, size);
	else if (!ft_strcmp(ssl->cmd, CMD_SHA384))
		result = sha384(query, size);
	if (!result)
		return ;
	if (ssl->options.p && !ssl->options.q)
		printf("(\"%.*s\")= %s\n", ft_strlen_special(query, size), query, result);
	else if (!ssl->options.p && !ssl->options.q)
		printf("(stdin)= %s\n", result);
	else if (ssl->options.q)
	{
		if (ssl->options.p)
			printf("%.*s\n", ft_strlen_special(query, size), query, result);
		printf("%s\n", result);
	}
	free(query);
	free(result);
}

int			main(int argc, char *argv[])
{
	t_ssl	ssl;

	if (check_args(argc, argv, &ssl))
	{
		clear_list(ssl.strings);
		clear_list(ssl.files);
		return (EXIT_FAILURE);
	}
	if (ssl.cmd)
	{
		if ((!ssl.strings && !ssl.files) || ssl.options.p)
			process_stdin(&ssl);
		process_strings(&ssl);
		process_files(&ssl);
	}
	clear_list(ssl.strings);
	clear_list(ssl.files);
	return (EXIT_SUCCESS);
}
