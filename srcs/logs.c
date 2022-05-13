#include "ft_ssl.h"

void		show_commands(int fd)
{
	char	*commands[NB_CMDS] = {"md5", "sha256", "sha512"};
	for (size_t i = 0; i < NB_CMDS; i++)
		dprintf(fd, "  %s\n", commands[i]);
}

void		show_options(int fd)
{
	char *options[NB_FLAGS][2] =
	{
		{"-p", "pipe STDIN to STDOUT and append the checksum to STDOUT"},
		{"-q", "quiet mode"},
		{"-r", "reverse the format of the output"},
		{"-s <string>", "print the sum of the given string"},
	};
	for (size_t i = 0; i < NB_FLAGS; i++)
		dprintf(fd, "  %-18s %s\n", options[i][0], options[i][1]);
}

void		show_usage(int fd)
{
	dprintf(fd, "usage: %s command [flags] [file/string]\n", PRG_NAME);
	dprintf(fd, "Commands:\n");
	show_commands(fd);
	dprintf(fd, "Options:\n");
	show_options(fd);
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
