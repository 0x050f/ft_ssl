#include "ft_ssl.h"

int			main(int argc, char *argv[])
{
	t_ssl	ssl;
	time_t	t;

	srand((unsigned) time(&t)); /* Initialize rand */
	if (check_args(argc, argv, &ssl))
	{
		clear_opt_arg(ssl.opt_args);
		return (EXIT_FAILURE);
	}
	if (ssl.cmd)
	{
		if (ssl.mode == MODE_HASH)
			process_hash(&ssl);
		else if (ssl.mode == MODE_CIPHER)
			process_cipher(&ssl);
	}
	clear_opt_arg(ssl.opt_args);
	return (EXIT_SUCCESS);
}
