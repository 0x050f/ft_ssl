#include "ft_ssl.h"

char		*launch_cipher(t_ssl *ssl, char *query, size_t size)
{
	char *cmds[NB_CIPHER_CMDS] = CMD_CIPHER;
	char *(*functions[NB_CIPHER_CMDS])(char *, size_t) = FUNC_CIPHER;

	for (int i = 0; i < NB_CIPHER_CMDS; i++)
	{
		if (!strcmp(ssl->cmd, cmds[i]))
			return (functions[i](query, size));
	}
	return (NULL);
}

void	process_cipher(t_ssl *ssl)
{
	char *str = launch_cipher(ssl, "bonjour", strlen("bonjour"));
	printf("%s\n", str);
	free(str);
}
