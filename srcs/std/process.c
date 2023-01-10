#include "ft_ssl.h"
#include "std.h"

char		*launch_std(char *cmd, char *query, size_t size, size_t *res_len, t_options *options) {
	char *cmds[NB_STD_CMDS][2] = CMD_STD;
	char *(*functions[NB_STD_CMDS])(uint8_t *, size_t, size_t *, t_options *) = FUNC_STD;

	for (int i = 0; i < NB_STD_CMDS; i++)
	{
		if (!strcmp(cmd, cmds[i][0]))
			return (functions[i]((unsigned char *)query, size, res_len, options));
	}
	return (NULL);
}

int		fill_std_options(t_options *options, t_ssl *ssl) {
	t_opt_arg *arg = get_last_arg(ssl->opt_args, "decrypt");
	int pos_d = arg ? arg->index : -1;
	arg = get_last_arg(ssl->opt_args, "encrypt");
	int pos_e = arg ? arg->index : -1;
	options->mode = (pos_e >= pos_d) ? CMODE_ENCRYPT : CMODE_DECRYPT;
	options->std_output = true;
	options->out = get_last_content(ssl->opt_args, "o");
	options->in = get_last_content(ssl->opt_args, "in");
	if (options->out && get_last_content(ssl->opt_args, "i")) {
		options->std_output = false;
	}
	options->inkey = get_last_content(ssl->opt_args, "inkey");
	options->inform = get_last_content(ssl->opt_args, "inform");
	options->outform = get_last_content(ssl->opt_args, "outform");
	options->passin = get_last_content(ssl->opt_args, "passin");
	options->passout = get_last_content(ssl->opt_args, "passout");
	options->des = get_last_arg(ssl->opt_args, "des") ? true : false;
	options->text = get_last_arg(ssl->opt_args, "text") ? true : false;
	options->noout = get_last_arg(ssl->opt_args, "noout") ? true : false;
	options->modulus = get_last_arg(ssl->opt_args, "modulus") ? true : false;
	options->check = get_last_arg(ssl->opt_args, "check") ? true : false;
	options->pubin = get_last_arg(ssl->opt_args, "pubin") ? true : false;
	options->pubout = get_last_arg(ssl->opt_args, "pubout") ? true : false;
	options->hexdump = get_last_arg(ssl->opt_args, "hexdump") ? true : false;
	return (0);
}

void	process_std_stdin(char *cmd, t_options *options) {
	size_t	ret;
	char	*result;

	result = launch_std(cmd, NULL, 0, &ret, options);
	printf("%.*s", ret, result);
}

void	process_std(t_ssl *ssl) {
	int				ret;
	t_options		options;

	memset(&options, 0, sizeof(t_options));
	ret = fill_std_options(&options, ssl);
	if (ret)
		return ;
	process_std_stdin(ssl->cmd, &options);
}
