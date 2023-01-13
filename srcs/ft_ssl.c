#include "ft_ssl.h"

int			main(int argc, char *argv[])
{
	int		ret;
	t_ssl	ssl;

	ret = 0;
	if (check_args(argc, argv, &ssl)) {
		clear_opt_arg(ssl.opt_args);
		return (EXIT_FAILURE);
	}
	if (ssl.cmd) {
		if (ssl.mode == MODE_HASH)
			ret = process_hash(&ssl);
		else if (ssl.mode == MODE_CIPHER)
			ret = process_cipher(&ssl);
		else if (ssl.mode == MODE_STD)
			ret = process_std(&ssl);
	}
	clear_opt_arg(ssl.opt_args);
	return (ret);
}
