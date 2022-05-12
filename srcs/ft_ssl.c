#include "ft_ssl.h"

int			main(int argc, char *argv[])
{
	t_ssl	ssl;

	if (check_args(argc, argv, &ssl))
	{
		clear_list(ssl.strings);
		clear_list(ssl.files);
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}
