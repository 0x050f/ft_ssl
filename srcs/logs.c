#include "ft_ssl.h"

void		show_commands(int fd, char *cmds[], int nb_cmds)
{
	for (int i = 0; i < nb_cmds; i++)
		dprintf(fd, "    %s\n", cmds[i]);
}

void		show_options(int fd, char *options[][3], int nb_options)
{
	int		padding = 18;

	for (int i = 0; i < nb_options; i++)
	{
		if (options[i][1])
			dprintf(fd, "    %s %-*s %s\n", options[i][0], (int)(padding - (ft_strlen(options[i][0]) + 1)), options[i][1], options[i][2]);
		else
			dprintf(fd, "    %-*s %s\n", padding, options[i][0], options[i][2]);
	}
}

void		show_usage(int fd)
{
	char	*hash_commands[NB_HASH_CMDS] = CMD_HASH;
	char	*hash_options[][3] = HASH_OPTIONS;
	char	*cipher_commands[NB_CIPHER_CMDS] = CMD_CIPHER;
	char	*cipher_options[][3] = CIPHER_OPTIONS;

	dprintf(fd, "usage: %s command [flags] [file/string]\n", PRG_NAME);
	dprintf(fd, "Commands:\n");
	dprintf(fd, "  Message Digest Commands:\n");
	show_commands(fd, hash_commands, NB_HASH_CMDS);
	dprintf(fd, "  Cipher Commands:\n");
	show_commands(fd, cipher_commands, NB_CIPHER_CMDS);
	dprintf(fd, "Options:\n");
	dprintf(fd, "  Hash Options:\n");
	show_options(fd, hash_options, NB_HASH_OPTIONS);
	dprintf(fd, "  Cipher Options:\n");
	show_options(fd, cipher_options, NB_CIPHER_OPTIONS);
	dprintf(fd, "    des only:\n");
	show_options(fd, &cipher_options[NB_CIPHER_OPTIONS], NB_CIPHER_DES_OPTIONS - NB_CIPHER_OPTIONS);
}

int			args_error(int error, char *str, int range1, int range2)
{
	dprintf(STDERR_FILENO, "%s: ", PRG_NAME);
	if (error == ERR_INV_OPT)
		dprintf(STDERR_FILENO, "invalid option -- '%s'\n", str);
	else if (error == ERR_INV_ARG || error == ERR_OOR_ARG)
	{
		dprintf(STDERR_FILENO, "invalid argument: '%s'", str);
		if (error == ERR_OOR_ARG)
			dprintf(STDERR_FILENO, ": out of range: %d <= value <= %d", range1, range2);
		dprintf(STDERR_FILENO, "\n");
	}
	else if (error == ERR_REQ_ARG)
		dprintf(STDERR_FILENO, "option requires an argument -- '%s'\n", str);
	return (2);
}
