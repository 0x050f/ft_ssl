#include "ft_ssl.h"

char		*search_option(char *to_search, char ***options, int nb_options)
{
	int i;

	for (i = 0; i < nb_options; i++)
	{
		if (!strncmp(to_search, (options[i][0] + 1), strlen((options[i][0] + 1))))
			break ;
	}
	if (i == nb_options)
		return (NULL);
	return (options[i][0]);
}

char		*get_string_arg(int argc, char *argv[], int *i, int j, char *arg)
{
	char	*str;

	if (argv[*i][j + 1])
		str = &argv[*i][j + 1];
	else if (argc  - 1 < *i + 1)
	{
		args_error(ERR_REQ_ARG, arg, 0, 0);
		return (NULL);
	}
	else
	{
		*i += 1;
		str = argv[*i];
	}
	return (str);
}

int			handle_cipher_option(int argc, char *argv[], int *i, int j, t_ssl *ssl, char *option)
{
	char *options[][3] = CIPHER_OPTIONS;

	for (int k = 0; k < NB_CIPHER_DES_OPTIONS; k++)
	{
		if (!strcmp(option, options[k][0]))
		{
			if (!strchr(ssl->options, *option))
				strcat(ssl->options, option);
			if (!strcmp(option, "-i"))
			{
				if (!(ssl->input = get_string_arg(argc, argv, i, j, option)))
					return (3);
				return (1);
			}
			else if (!strcmp(option, "-o"))
			{
				if (!(ssl->output = get_string_arg(argc, argv, i, j, option)))
					return (3);
				return (1);
			}
			else if (!strcmp(option, "-k"))
			{
				if (!(ssl->key = get_string_arg(argc, argv, i, j, option)))
					return (3);
				if ((ft_strlen(ssl->key) % 2) || !ishexa(ssl->key))
					return (args_error(ERR_HEX_ARG, "k", 0, 0) + 1);
				return (1);
			}
			else if (!strcmp(option, "-p"))
			{
				if (!(ssl->password = get_string_arg(argc, argv, i, j, option)))
					return (3);
				if (!isprintable(ssl->password))
					return (args_error(ERR_PRINT_ARG, "p", 0, 0) + 1);
				return (1);
			}
			else if (!strcmp(option, "-s"))
			{
				if (!(ssl->salt = get_string_arg(argc, argv, i, j, option)))
					return (3);
				if ((ft_strlen(ssl->salt) % 2) || !ishexa(ssl->salt))
					return (args_error(ERR_HEX_ARG, "s", 0, 0) + 1);
				return (1);
			}
			else if (!strcmp(option, "-v"))
			{
				if (!(ssl->iv = get_string_arg(argc, argv, i, j, option)))
					return (3);
				if ((ft_strlen(ssl->iv) % 2) || !ishexa(ssl->iv))
					return (args_error(ERR_HEX_ARG, "v", 0, 0) + 1);
				return (1);
			}
		}
	}
	return (0);
}

int			handle_hash_option(int argc, char *argv[], int *i, int j, t_ssl *ssl, char *option)
{
	char *options[][3] = HASH_OPTIONS;

	for (int k = 0; k < NB_HASH_OPTIONS; k++)
	{
		if (!strcmp(option, options[k][0]))
		{
			if (!strchr(ssl->options, options[k][0][1]))
				strcat(ssl->options, &options[k][0][1]);
			if (!strcmp(option, "-s"))
			{
				char *str;
				if (!(str = get_string_arg(argc, argv, i, j, option)))
					return (3);
				if (!add_list(&ssl->strings, str))
				{
					dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
					return (ERR_MALLOC + 1);
				}
				return (1);
			}
		}
	}
	return (0);
}

int			handle_options(int argc, char *argv[], int *i, t_ssl *ssl, t_cmd_options *cmd_options)
{
	int		ret;
	int		j;

	j = 1;
	while (argv[*i][j])
	{
		char *option = search_option(&argv[*i][j], cmd_options->options, cmd_options->nb_options);
		if (!option)
			goto error;
		else if ((ret = (*cmd_options->handler)(argc, argv, i, j, ssl, option)))
			return (ret - 1);
		j++;
	}
	return (0);
	char letter[2] = {0, 0};
	error:
		letter[0] = argv[*i][j];
		letter[1] = 0;
		args_error(ERR_INV_OPT, letter, 0, 0);
		return (2);
}

int			setup_cmd_options(t_cmd_options *cmd_options, int ((*handler)(int, char **, int *, int, t_ssl *, char *)), int nb_options, char *options[][3])
{
	int i;

	cmd_options->handler = handler;
	cmd_options->nb_options = nb_options;
	cmd_options->options = malloc(sizeof(char **) * nb_options);
	if (!cmd_options->options)
		goto error;
	for (i = 0; i < nb_options; i++)
	{
		cmd_options->options[i] = malloc(sizeof(char *) * 3);
		if (!cmd_options->options[i])
			goto free_everything;
		for (int j = 0; j < 3; j++)
		{
			if (options[i][j] && !(cmd_options->options[i][j] = ft_strdup(options[i][j])))
			{
				while (--j > 0)
					free(cmd_options->options[i][j]);
				free(cmd_options->options[i]);
				goto free_everything;
			}
			else if(!options[i][j])
				cmd_options->options[i][j] = NULL;
		}
	}
	return (0);
	free_everything:
		for (int j = 0; j < i - 1; j++)
		{
			for (int k = 0; k < 3; k++)
				free(cmd_options->options[j][k]);
			free(cmd_options->options[j]);
		}
		free(cmd_options->options);
	error:
		dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
		return (ERR_MALLOC);
}

void		free_options(char ***options, int nb_options)
{
	for (int i = 0; i < nb_options; i++)
	{
		for (int j = 0; j < 3; j++)
			free(options[i][j]);
		free(options[i]);
	}
	free(options);
}

int			search_command(char *cmd, char *cmds[], int nb_cmds)
{
	int i = 0;
	while (i < nb_cmds && ft_strcmp(cmd, cmds[i]))
		i++;
	return (i);
}

int			check_args(int argc, char *argv[], t_ssl *ssl)
{
	int				ret;
	char			*hash_cmds[NB_HASH_CMDS] = CMD_HASH;
	char			*cipher_cmds[NB_CIPHER_CMDS] = CMD_CIPHER;
	t_cmd_options	cmd_options;

	memset(ssl, 0, sizeof(t_ssl));
	if (argc < 2)
	{
		show_usage(STDOUT_FILENO);
		return (0);
	}
	int i = search_command(argv[1], hash_cmds, NB_HASH_CMDS);
	if (i != NB_HASH_CMDS)
	{
		char		*options[][3] = HASH_OPTIONS;

		if (setup_cmd_options(&cmd_options, &handle_hash_option, NB_HASH_OPTIONS, options))
			return (ERR_MALLOC);
	}
	else
	{
		i = search_command(argv[1], cipher_cmds, NB_CIPHER_CMDS);
		if (i != NB_CIPHER_CMDS)
		{
			int			nb_options;
			char		*options[][3] = CIPHER_OPTIONS;

			if (!ft_strcmp(argv[1], "base64"))
				nb_options = NB_CIPHER_OPTIONS;
			else
				nb_options = NB_CIPHER_DES_OPTIONS;
			if (setup_cmd_options(&cmd_options, &handle_cipher_option, nb_options, options))
				return (ERR_MALLOC);
		}
		else
		{
			dprintf(STDERR_FILENO, "%s: Error: '%s' is an invalid command.\n\n", PRG_NAME, argv[1]);
			show_usage(STDERR_FILENO);
			return (ERR_BADCMD);
		}
	}
	ssl->cmd = argv[1];
	i = 2;
	while (i < argc && *argv[i] == '-')
	{
		ret = handle_options(argc, argv, &i, ssl, &cmd_options);
		if (ret)
		{
			free_options(cmd_options.options, cmd_options.nb_options);
			return (ret);
		}
		i++;
	}
	while (i < argc)
	{
		if (!add_list(&ssl->files, argv[i]))
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			free_options(cmd_options.options, cmd_options.nb_options);
			return (ERR_MALLOC);
		}
		i++;
	}
	free_options(cmd_options.options, cmd_options.nb_options);
	return (0);
}
