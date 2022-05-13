#include "ft_ssl.h"

int			handle_options(int argc, char *argv[], int *i, t_ssl *ssl)
{
	int		j;
	int		k;
	char	options[NB_FLAGS] = {'p', 'q', 'r', 's'};

	k = 0;
	j = 1;
	while (argv[*i][j])
	{
		k = 0;
		while (k < NB_FLAGS)
		{
			if (argv[*i][j] == options[k])
				break ;
			k++;
		}
		if (k == NB_FLAGS)
			break ;
		else
		{
			if (options[k] == 'p')
				ssl->options.p = 1;
			else if (options[k] == 'q')
				ssl->options.q = 1;
			else if (options[k] == 'r')
				ssl->options.r = 1;
			else if (options[k] == 's')
			{
				char *str;

				if (argv[*i][j + 1])
					str = &argv[*i][j + 1];
				else if (argc  - 1 < *i + 1)
					return (args_error(ERR_REQ_ARG, "s", 0, 0));
				else
				{
					*i += 1;
					str = argv[*i];
				}
				if (!add_list(&ssl->strings, str))
				{
					dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
					return (ERR_MALLOC);
				}
				ssl->options.s = 1;
				return (0);
			}
		}
		j++;
	}
	if (k == NB_FLAGS)
	{
		char option[2] = {0, 0};
		option[0] = argv[*i][j];
		args_error(ERR_INV_OPT, option, 0, 0);
		return (2);
	}
	return (0);
}

int			check_args(int argc, char *argv[], t_ssl *ssl)
{
	char	*commands[NB_CMDS] = {"md5", "sha256", "sha512", "sha384"};
	int		ret;

	ft_memset(ssl, 0, sizeof(t_ssl));
	if (argc < 2)
	{
		show_usage(STDOUT_FILENO);
		return (0);
	}
	ft_memset(&ssl->options, 0, sizeof(t_options));
	int i = 0;
	while (i < NB_CMDS && ft_strcmp(argv[1], commands[i]))
		i++;
	if (i == NB_CMDS)
	{
		dprintf(STDERR_FILENO, "%s: Error: '%s' is an invalid command.\n\n", PRG_NAME, argv[1]);
		show_usage(STDERR_FILENO);
		return (ERR_BADCMD);
	}
	else
		ssl->cmd = argv[1];
	i = 2;
	while (i < argc && *argv[i] == '-')
	{
		ret = handle_options(argc, argv, &i, ssl);
		if (ret)
			return (ret);
		i++;
	}
	while (i < argc)
	{
		if (!add_list(&ssl->files, argv[i]))
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			return (ERR_MALLOC);
		}
		i++;
	}
	return (0);
}
