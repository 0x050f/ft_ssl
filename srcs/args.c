#include "ft_ssl.h"

char		**search_long_option(char *to_search, char ***options, int nb_options)
{
	char *str;
	int i;

	for (i = 0; i < nb_options; i++)
	{
		if (options[i][INDEX_FULLNAME]) {
			str = options[i][INDEX_FULLNAME];
			if (!strncmp(to_search, str, strlen(str)))
				break;
		}
	}
	if (i == nb_options)
		return (NULL);
	return (options[i]);
}

char		**search_short_option(char *to_search, char ***options, int nb_options)
{
	char *str;
	int i;

	for (i = 0; i < nb_options; i++)
	{
		if (options[i][INDEX_NAME]) {
			str = strrchr(options[i][INDEX_NAME], '-') + 1;
			if (!strncmp(to_search, str, strlen(str)))
				break;
		}
	}
	if (i == nb_options)
		return (NULL);
	return (options[i]);
}

char		*get_string_arg(int argc, char *argv[], int *i, int j, char *arg)
{
	char	*str;

	str = &argv[*i][j];
	if (!*str) {
		if (argc - 1 < *i + 1) {
			args_error(ERR_REQ_ARG, arg, 0, 0);
			return (NULL);
		} else {
			*i += 1;
			str = argv[*i];
		}
	}
	return (str);
}

int			append_option(int argc, char *argv[], int *i, int j, t_ssl *ssl, char **option, char *name)
{
	t_opt_arg *ret;
	char	*str;

	if (option[INDEX_ARG]) // has an argument
	{
		if (!(str = get_string_arg(argc, argv, i, j, name)))
			return (ERR_REQ_ARG);
		if (option[INDEX_CHECK] &&
			!strcmp(option[INDEX_CHECK], "HEX") && (!ishexa(str))) // should be hexa
			return (args_error(ERR_HEX_ARG, name, 0, 0) + 1);
		else if (option[INDEX_CHECK] &&
			!strcmp(option[INDEX_CHECK], "PRINT") && !isprintable(str)) // should be printable
			return (args_error(ERR_PRINT_ARG, name, 0, 0) + 1);
		if (option[INDEX_NAME])
			ret = append_opt_arg(&ssl->opt_args, strrchr(option[INDEX_NAME], '-') + 1, str);
		else
			ret = append_opt_arg(&ssl->opt_args, strrchr(option[INDEX_FULLNAME], '-') + 1, str);
		if (!ret)
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			return (ERR_MALLOC);
		}
		return (1);
	} else {
		if (option[INDEX_NAME])
			ret = append_opt_arg(&ssl->opt_args, strrchr(option[INDEX_NAME], '-') + 1, NULL);
		else
			ret = append_opt_arg(&ssl->opt_args, strrchr(option[INDEX_FULLNAME], '-') + 1, NULL);
	}
	return (0);
}

int			handle_options(
	int argc,
	char *argv[],
	int *i,
	t_ssl *ssl,
	t_cmd_options *cmd_options
) {
	int		ret;
	int		j;

	j = 0;
	if (!strcmp(&argv[*i][j], "--help")) {
		show_cmd(STDOUT_FILENO, ssl->cmd, cmd_options);
		ssl->cmd = NULL;
		return (0);
	}
	char **option = search_long_option(
		&argv[*i][j], cmd_options->options, cmd_options->nb_options
	);
	if (!option) {
		j++;
		if (!strcmp(&argv[*i][j], "h"))
		{
			show_cmd(STDOUT_FILENO, ssl->cmd, cmd_options);
			ssl->cmd = NULL;
			return (0);
		}
		else if (!strcmp(ssl->cmd, "genrsa") || !strcmp(ssl->cmd, "rsa")) {
			//TODO add cipher etc..
			return (0);
		}
		while (argv[*i][j]) {
			char **option = search_short_option(
				&argv[*i][j], cmd_options->options, cmd_options->nb_options
			);
			if (!option && j != 1) { // not first opt
				char letter[2] = {argv[*i][j], 0};

				args_error(ERR_INV_OPT, letter, 0, 0);
				return (2);
			} else if (!option) { // first opt of arg
				args_error(ERR_INV_OPT, argv[*i], 0, 0);
				return (2);
			} else {
				j++;
				ret = append_option(argc, argv, i, j, ssl, option, option[INDEX_NAME] + 1);
				if (ret > 1)
					return (ret);
				else if (ret == 1)
					return (0);
			}
		}
		return (0);
	}
	j = strlen(option[INDEX_FULLNAME]);
	if ((ret = append_option(argc, argv, i, j, ssl, option, option[INDEX_FULLNAME] + 2)) > 1)
		return (ret);
	return (0);
}

int			setup_cmd_options(
	t_cmd_options *cmd_options,
	int nb_options,
	char *options[][NB_COLUMNS_OPTIONS],
	char *option_list
) {
	int i, k;
	int nb_opt;
	char opt_tmp[strlen(option_list) + 1];
	char *ptr;

	strcpy(opt_tmp, option_list);
	nb_opt = 0;
	ptr = strtok(opt_tmp, ",");
	while (ptr) {
		if (*ptr)
			nb_opt++;
		ptr = strtok(NULL, ",");
	}
	cmd_options->nb_options = nb_opt;
	cmd_options->options = malloc(sizeof(char **) * nb_opt);
	if (!cmd_options->options)
		goto error;
	strcpy(opt_tmp, option_list);
	ptr = strtok(opt_tmp, ",");
	k = 0;
	while (ptr) {
		for (i = 0; i < nb_options; i++) {
			if ((options[i][INDEX_NAME] && !strcmp(ptr, strrchr(options[i][INDEX_NAME], '-') + 1)) ||
			(options[i][INDEX_FULLNAME] &&!strcmp(ptr, strrchr(options[i][INDEX_FULLNAME], '-') + 1))) {
				cmd_options->options[k] = malloc(sizeof(char *) * NB_COLUMNS_OPTIONS);
				if (!cmd_options->options[k])
					goto free_everything;
				for (int j = 0; j < NB_COLUMNS_OPTIONS; j++)
				{
					if (options[i][j] && !(cmd_options->options[k][j] = strdup(options[i][j]))) {
						while (--j > 0)
							free(cmd_options->options[k][j]);
						free(cmd_options->options[k]);
						goto free_everything;
					} else if(!options[i][j])
						cmd_options->options[k][j] = NULL;
				}
				k++;
				break ;
			}
		}
		ptr = strtok(NULL, ",");
	}
	cmd_options->nb_options = k; /* avoid problems if define are malformed */
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

int			search_command(char *cmd, char *cmds[][2], int nb_cmds)
{
	int i = 0;
	while (i < nb_cmds && strcmp(cmd, cmds[i][0]))
		i++;
	return (i);
}

int			compute_options(int argc, char *argv[], t_ssl *ssl, t_cmd_options *cmd_options) {
	int i, ret;

	ssl->cmd = argv[1];
	i = 2;
	while (i < argc && *argv[i] == '-') {
		ret = handle_options(argc, argv, &i, ssl, cmd_options);
		if (ret) {
			free_options(cmd_options->options, cmd_options->nb_options);
			return (ret);
		}
		i++;
	}
	while (i < argc) {
		if (ssl->mode == MODE_HASH) {
			if (!append_opt_arg(&ssl->opt_args, "f", argv[i])) { // add files (HASH)
				dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
				free_options(cmd_options->options, cmd_options->nb_options);
				return (ERR_MALLOC);
			}
			i++;
		} else {
			args_error(ERR_INV_ARG, argv[i], 0, 0);
			free_options(cmd_options->options, cmd_options->nb_options);
			return (ERR_INV_ARG);
		}
	}
	free_options(cmd_options->options, cmd_options->nb_options);
	return (0);
}

int			check_args(int argc, char *argv[], t_ssl *ssl)
{
	int				i;
	char			*std_cmds[NB_STD_CMDS][2] = CMD_STD;
	char			*hash_cmds[NB_HASH_CMDS][2] = CMD_HASH;
	char			*cipher_cmds[NB_CIPHER_CMDS][2] = CMD_CIPHER;
	t_cmd_options	cmd_options;

	memset(ssl, 0, sizeof(t_ssl));
	if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
	{
		show_usage(STDOUT_FILENO);
		return (0);
	}
	i = search_command(argv[1], hash_cmds, NB_HASH_CMDS);
	if (i != NB_HASH_CMDS)
	{
		char *options[][NB_COLUMNS_OPTIONS] = HASH_OPTIONS;

		ssl->mode = MODE_HASH;
		if (setup_cmd_options(&cmd_options, NB_HASH_OPTIONS, options, hash_cmds[i][1]))
			return (ERR_MALLOC);
		return (compute_options(argc, argv, ssl, &cmd_options));
	}
	i = search_command(argv[1], cipher_cmds, NB_CIPHER_CMDS);
	if (i != NB_CIPHER_CMDS)
	{
		char *options[][NB_COLUMNS_OPTIONS] = CIPHER_OPTIONS;

		ssl->mode = MODE_CIPHER;
		if (setup_cmd_options(&cmd_options, NB_CIPHER_OPTIONS, options, cipher_cmds[i][1])) 
			return (ERR_MALLOC);
		return (compute_options(argc, argv, ssl, &cmd_options));
	}
	i = search_command(argv[1], std_cmds, NB_STD_CMDS);
	if (i != NB_STD_CMDS)
	{
		char *options[][NB_COLUMNS_OPTIONS] = STD_OPTIONS;

		ssl->mode = MODE_STD;
		if (setup_cmd_options(&cmd_options, NB_STD_OPTIONS, options, std_cmds[i][1]))
			return (ERR_MALLOC);
		return (compute_options(argc, argv, ssl, &cmd_options));
	}
	dprintf(STDERR_FILENO, "%s: Error: '%s' is an invalid command.\n\n", PRG_NAME, argv[1]);
	show_usage(STDERR_FILENO);
	return (ERR_BADCMD);
}
