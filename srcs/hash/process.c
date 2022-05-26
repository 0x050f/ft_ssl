#include "ft_ssl.h"

char		*launch_hash(t_ssl *ssl, char *query, size_t size)
{
	char *cmds[NB_HASH_CMDS] = CMD_HASH;
	char *(*functions[NB_HASH_CMDS])(char *, size_t) = FUNC_HASH;

	for (int i = 0; i < NB_HASH_CMDS; i++)
	{
		if (!strcmp(ssl->cmd, cmds[i]))
			return (functions[i](query, size));
	}
	return (NULL);
}

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
			memcpy(tmp, query, *size);
		memcpy(tmp + *size, buffer, ret);
		free(query);
		*size += ret;
		query = tmp;
	}
	return (query);
}

void		process_hash_files(t_ssl *ssl)
{
	t_opt_arg	*tmp;
	size_t		size;
	char		*query;
	char		*result;

	tmp = ssl->opt_args;
	while (tmp)
	{
		if (tmp->arg == 'f')
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
			result = launch_hash(ssl, query, size);
			if (!result)
				return ;
			if (!strchr(ssl->options, 'q') && !strchr(ssl->options, 'r'))
			{
				char uppercase[12];

				strcpy(uppercase, ssl->cmd);
				ft_toupper(uppercase);
				printf("%s(%s)= ", uppercase, tmp->content);
			}
			printf("%s", result);
			if (!strchr(ssl->options, 'q') && strchr(ssl->options, 'r'))
				printf(" %s", tmp->content);
			printf("\n");
			free(query);
			free(result);
			close(fd);
		}
		tmp = tmp->next;
	}
}

void		process_hash_strings(t_ssl *ssl)
{
	t_opt_arg	*tmp;
	char		*result;

	tmp = ssl->opt_args;
	while (tmp)
	{
		if (tmp->arg == 's')
		{
			result = launch_hash(ssl, tmp->content, strlen(tmp->content));
			if (!result)
				return ;
			if (!strchr(ssl->options, 'q') && !strchr(ssl->options, 'r'))
			{
				char uppercase[12];

				strcpy(uppercase, ssl->cmd);
				ft_toupper(uppercase);
				printf("%s(\"%s\")= ", uppercase, tmp->content);
			}
			printf("%s", result);
			if (!strchr(ssl->options, 'q') && strchr(ssl->options, 'r'))
				printf(" \"%s\"", tmp->content);
			printf("\n");
			free(result);
		}
		tmp = tmp->next;
	}
}

void		process_hash_stdin(t_ssl *ssl)
{
	size_t	size;
	char	*query;
	char	*result;

	if (!(query = read_query(STDIN_FILENO, &size)))
		return ;
	result = launch_hash(ssl, query, size);
	if (!result)
		return ;
	if (strchr(ssl->options, 'p') && !strchr(ssl->options, 'q'))
		printf("(\"%.*s\")= %s\n", ft_strlen_special(query, size), query, result);
	else if (!strchr(ssl->options, 'p') && !strchr(ssl->options, 'q'))
		printf("(stdin)= %s\n", result);
	else if (strchr(ssl->options, 'q'))
	{
		if (strchr(ssl->options, 'p'))
			printf("%.*s\n", ft_strlen_special(query, size), query, result);
		printf("%s\n", result);
	}
	free(query);
	free(result);
}

void		process_hash(t_ssl *ssl)
{
	if ((!strchr(ssl->options, 's') && !strchr(ssl->options, 'f')) || strchr(ssl->options, 'p'))
		process_hash_stdin(ssl);
	process_hash_strings(ssl);
	process_hash_files(ssl);
}
