#include "ft_ssl.h"

char		**search_option(char *to_search, char ***options, int nb_options)
{
	int i;

	for (i = 0; i < nb_options; i++)
	{
		if (!strncmp(to_search, (options[i][0] + 1), strlen((options[i][0] + 1))))
			break ;
	}
	if (i == nb_options)
		return (NULL);
	return (options[i]);
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

int			append_option(int argc, char *argv[], int *i, int j, t_ssl *ssl, char **option)
{
	char	*str;

	if (!(str = strchr(ssl->options, option[0][1]))) // append the option
		ssl->options[strlen(ssl->options)] = option[0][1];
	else
	{
		memmove(str, str + 1, strlen(str + 1));
		ssl->options[strlen(ssl->options) - 1] = option[0][1];
	}
	if (option[1]) // has an argument
	{
		if (!(str = get_string_arg(argc, argv, i, j, &option[0][1])))
			return (ERR_REQ_ARG);
		if (option[3] && !strcmp(option[3], "HEX") && (!ishexa(str))) // should be hexa
			return (args_error(ERR_HEX_ARG, &option[0][1], 0, 0) + 1);
		else if (option[3] && !strcmp(option[3], "PRINT") && !isprintable(str)) // should be printable
			return (args_error(ERR_PRINT_ARG, &option[0][1], 0, 0) + 1);
		if (!append_opt_arg(&ssl->opt_args, option[0][1], str))
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			return (ERR_MALLOC);
		}
		return (1);
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
		char **option = search_option(&argv[*i][j], cmd_options->options, cmd_options->nb_options);
		if (!option)
			goto error;
		else 
		{
			ret = append_option(argc, argv, i, j, ssl, option);
			if (ret > 1)
				return (ret);
			else if (ret == 1)
				return (0);
		}
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

int			setup_cmd_options(t_cmd_options *cmd_options, int nb_options, char *options[][NB_COLUMNS_OPTIONS])
{
	int i;

	cmd_options->nb_options = nb_options;
	cmd_options->options = malloc(sizeof(char **) * nb_options);
	if (!cmd_options->options)
		goto error;
	for (i = 0; i < nb_options; i++)
	{
		cmd_options->options[i] = malloc(sizeof(char *) * NB_COLUMNS_OPTIONS);
		if (!cmd_options->options[i])
			goto free_everything;
		for (int j = 0; j < NB_COLUMNS_OPTIONS; j++)
		{
			if (options[i][j] && !(cmd_options->options[i][j] = strdup(options[i][j])))
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
			for (int k = 0; k < NB_COLUMNS_OPTIONS; k++)
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
		for (int j = 0; j < NB_COLUMNS_OPTIONS; j++)
			free(options[i][j]);
		free(options[i]);
	}
	free(options);
}

int			search_command(char *cmd, char *cmds[], int nb_cmds)
{
	int i = 0;
	while (i < nb_cmds && strcmp(cmd, cmds[i]))
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
		char		*options[][NB_COLUMNS_OPTIONS] = HASH_OPTIONS;

		ssl->mode = MODE_HASH;
		if (setup_cmd_options(&cmd_options, NB_HASH_OPTIONS, options))
			return (ERR_MALLOC);
	}
	else
	{
		i = search_command(argv[1], cipher_cmds, NB_CIPHER_CMDS);
		if (i != NB_CIPHER_CMDS)
		{
			int			nb_options;
			char		*options[][NB_COLUMNS_OPTIONS] = CIPHER_OPTIONS;

			ssl->mode = MODE_CIPHER;
			if (!strcmp(argv[1], "base64"))
				nb_options = NB_CIPHER_OPTIONS;
			else
				nb_options = NB_CIPHER_DES_OPTIONS;
			if (setup_cmd_options(&cmd_options, nb_options, options))
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
		if (ssl->mode == MODE_HASH)
		{
			if (!strchr(ssl->options, 'f')) // append the option
				strcat(ssl->options, "f");
			if (!append_opt_arg(&ssl->opt_args, 'f', argv[i])) // add files (HASH)
			{
				dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
				free_options(cmd_options.options, cmd_options.nb_options);
				return (ERR_MALLOC);
			}
			i++;
		}
		else
		{
			args_error(ERR_INV_ARG, argv[i], 0, 0);
			free_options(cmd_options.options, cmd_options.nb_options);
			return (ERR_INV_ARG);
		}
	}
	free_options(cmd_options.options, cmd_options.nb_options);
	return (0);
}
