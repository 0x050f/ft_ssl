#include "ft_ssl.h"

void		show_commands(int fd, char *cmds[][2], int nb_cmds)
{
	for (int i = 0; i < nb_cmds; i++)
		dprintf(fd, "    %s\n", cmds[i][0]);
}

void		show_options(int fd, char *options[][NB_COLUMNS_OPTIONS], int nb_options)
{
	int		sum;

	for (int i = 0; i < nb_options; i++)
	{
		sum = 0;
		if (options[i][INDEX_NAME]) {
			dprintf(fd, "    %s", options[i][INDEX_NAME]);
			sum += strlen(options[i][INDEX_NAME]) + 4;
			if (options[i][INDEX_FULLNAME]) {
				dprintf(fd, ", %s", options[i][INDEX_FULLNAME]);
				sum += strlen(options[i][INDEX_FULLNAME]) + 2;
			}
		} else {
			dprintf(fd, "    %s", options[i][INDEX_FULLNAME]);
			sum += strlen(options[i][INDEX_FULLNAME]) + 4;
		}
		if (options[i][INDEX_ARG]) {
			dprintf(fd, "%*s%s", PADDING_ARG - sum, "", options[i][INDEX_ARG]);
			sum += strlen(options[i][INDEX_ARG]) + (PADDING_ARG - sum);
		}
		dprintf(fd, "%*s%s\n", PADDING_DESC - sum, "", options[i][INDEX_DESC]);
	}
}

void		show_usage(int fd)
{
	char	*std_commands[NB_STD_CMDS][2] = CMD_STD;
	char	*std_options[][NB_COLUMNS_OPTIONS] = STD_OPTIONS;
	char	*hash_commands[NB_HASH_CMDS][2] = CMD_HASH;
	char	*hash_options[][NB_COLUMNS_OPTIONS] = HASH_OPTIONS;
	char	*cipher_commands[NB_CIPHER_CMDS][2] = CMD_CIPHER;
	char	*cipher_options[][NB_COLUMNS_OPTIONS] = CIPHER_OPTIONS;

	dprintf(fd, "usage: %s command [flags] [file/string]\n", PRG_NAME);
	dprintf(fd, "Commands:\n");
	dprintf(fd, "  Standard Commands:\n");
	show_commands(fd, std_commands, NB_STD_CMDS);
	dprintf(fd, "  Message Digest Commands:\n");
	show_commands(fd, hash_commands, NB_HASH_CMDS);
	dprintf(fd, "  Cipher Commands:\n");
	show_commands(fd, cipher_commands, NB_CIPHER_CMDS);
	dprintf(fd, "Options:\n");
	dprintf(fd, "  Standard Options:\n");
	show_options(fd, std_options, NB_STD_OPTIONS);
	dprintf(fd, "  Hash Options:\n");
	show_options(fd, hash_options, NB_HASH_OPTIONS);
	dprintf(fd, "  Cipher Options:\n");
	show_options(fd, cipher_options, NB_CIPHER_OPTIONS);
}

int			args_error(int error, char *str, int range1, int range2)
{
	dprintf(STDERR_FILENO, "%s: ", PRG_NAME);
	if (error == ERR_INV_OPT)
		dprintf(STDERR_FILENO, "invalid option -- '%s'\n", str);
	else if (error == ERR_INV_ARG || error == ERR_OOR_ARG || error == ERR_HEX_ARG || error == ERR_PRINT_ARG)
	{
		dprintf(STDERR_FILENO, "invalid argument: '%s'", str);
		if (error == ERR_OOR_ARG)
			dprintf(STDERR_FILENO, ": out of range: %d <= value <= %d", range1, range2);
		else if (error == ERR_HEX_ARG)
			dprintf(STDERR_FILENO, ": must be in lowercase hexadecimal ([0-9a-f])");
		else if (error == ERR_PRINT_ARG)
			dprintf(STDERR_FILENO, ": must be printable (' ' <= x <= '~')");
		dprintf(STDERR_FILENO, "\n");
	}
	else if (error == ERR_REQ_ARG)
		dprintf(STDERR_FILENO, "option requires an argument -- '%s'\n", str);
	return (2);
}
