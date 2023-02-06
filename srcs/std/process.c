#include "ft_ssl.h"
#include "std.h"

uint64_t	custom_rand(void) {
	uint64_t	result;
	int			ret, fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		dprintf(STDERR_FILENO, "%s: open: /dev/urandom: %s\n", PRG_NAME, strerror(errno));
		return (-1);
	}
	ret = read(fd, &result, sizeof(result));
	if (ret < 0) {
		dprintf(STDERR_FILENO, "%s: read: /dev/urandom: %s\n", PRG_NAME, strerror(errno));
		return (-1);
	}
	close(fd);
	return (result);
}

uint64_t	rand_range(uint64_t min, uint64_t max) {
	return (custom_rand() % (max + 1 - min) + min);
}

/* Return x^n % p fast */
uint64_t	power_mod(uint64_t x, uint64_t n, uint64_t p) {
	uint64_t z = 1;

	while (n) {
		if (n % 2) {
			z = ((unsigned __int128)z * x) % p;
		}
		n /= 2;
		x = ((unsigned __int128)x * x) % p;
	}
	return (z);
}

bool		miller(uint64_t n, uint64_t a) {
	int			s;
	uint64_t	d, x;

	s = 0;
	d = n - 1;
	while (!(d % 2)) { // n - 1 = (2 ^ s) * d
		s++;
		d /= 2;
	}
	x = power_mod(a, d, n);
	if (x == 1 || x == n - 1) {
		return (false);
	}
	while (s-- > 0) {
		x = power_mod(x, 2, n);
		if (x == n - 1) {
			return (false);
		}
	}
	return (true);
}

// Return true if integer n is probably prime (n odd > 2, k > 0)
bool		miller_rabin(uint64_t n, int k) {
	if (n == 2 || n == 3) {
		return (true);
	}
	if (n <= 1 || !(n % 2)) {
		return (false);
	}
	uint64_t a;

	while (k-- > 0) {
		a = rand_range(2, n - 2);
		if (miller(n, a)) {
			return (false);
		}
	}
	return (true);
}

/* https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm */
unsigned __int128	inv_mod(unsigned __int128 a, unsigned __int128 n) {
	__int128 t = 0;
	__int128 newt = 1;
	unsigned __int128 r = n;
	unsigned __int128 newr = a;

	while (newr) {
		__int128 tmp;
		unsigned __int128 quotient = r / newr;
		// (t, newt) := (newt, t - quotient * newt)
		tmp = newt;
		newt = t - quotient * newt;
		t = tmp;
		// (r, newr) := (newr, r - quotient * newr)
		tmp = newr;
		newr = r - quotient * newr;
		r = tmp;
	}
	if (r > 1)
		return (0); // not invertible
	if (t < 0)
		t += n;
	return (t);
}

unsigned __int128	pgcd_binary(unsigned __int128 a, unsigned __int128 b) {
	if (!b)
		return (1);
	if (!a)
		return (b);
	if (!(a % 2) && !(b % 2))
		return (2 * pgcd_binary(a / 2, b / 2));
	if ((a % 2) && !(b % 2))
		return (pgcd_binary(a, b / 2));
	if (!(a % 2) && (b % 2))
		return (pgcd_binary(a / 2, b));
	if (a < b) {
		unsigned __int128 tmp = a;
		a = b;
		b = tmp;
	}
	return (pgcd_binary((a - b)/2, b));
}

bool		check_prime(uint64_t n, double proba) {
	if (!(proba >= 0.0 && proba <= 1.0))
		return (false);

	double nb_round = 1.0;
	// miller-rabin: 75% chance on each round to detect a non-prime value
	while (pow(0.25, nb_round) > 1.0 - proba) {
		nb_round += 1;
	}
	/* Solovay-Strassen < Miller-Rabin speed */
	return (miller_rabin(n, nb_round));
}

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

void	print_std_result(char *result, size_t result_size, char *cmd, t_options *options) {
	(void)cmd;
	if (!result_size)
		return ;
	if (options->std_output) {
		if (result[result_size - 1] != '\n')
			dprintf(STDOUT_FILENO, "%.*s\n", (int)result_size, result);
		else
			dprintf(STDOUT_FILENO, "%.*s", (int)result_size, result);
	}
	if (options->out) {
		int rights = (options->pubout) ? 0644 : 0600; // Create locked file if private key
		int fd = open(options->out, O_CREAT | O_WRONLY | O_TRUNC, rights);
		if (fd < 0) {
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->out, strerror(errno));
			return ;
		}
		if (result[result_size - 1] != '\n')
			dprintf(fd, "%.*s\n", (int)result_size, result);
		else
			dprintf(fd, "%.*s", (int)result_size, result);
		close(fd);
	}
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
	if (options->out && !get_last_arg(ssl->opt_args, "i")) {
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
	// Get last cipher if exist (for 'genrsa' and 'rsa' cmds)
	char *cipher[NB_CIPHER_CMDS][2] = CMD_CIPHER;
	int idx[NB_CIPHER_CMDS];
	for (size_t i = 0; i < NB_CIPHER_CMDS; i++)
		idx[i] = -1;
	for (size_t i = 0; i < NB_CIPHER_CMDS; i++) {
		arg = get_last_arg(ssl->opt_args, cipher[i][0]);
		if (arg) {
			idx[i] = arg->index;
		}
	}
	int max_idx = -1;
	for (size_t i = 0; i < NB_CIPHER_CMDS; i++) {
		if ((max_idx == -1 && idx[i] != -1) || (max_idx != -1 && idx[i] > idx[max_idx]))
			max_idx = i;
	}
	if (max_idx != -1)
		options->cipher = cipher[max_idx][0];
	return (0);
}

int		process_std_stdin(char *cmd, t_options *options) {
	size_t	ret;
	size_t	size;
	char	*query;
	char	*result;

	query = NULL;
	size = 0;
	if (!strcmp(cmd, "rsa")) {
		if (!(query = read_query(STDIN_FILENO, &size)))
			return (1);
	}
	result = launch_std(cmd, query, size, &ret, options);
	free(query);
	if (!result) {
		return (1);
	}
	print_std_result(result, ret, cmd, options);
	free(result);
	return (0);
}

int		process_std_file(char *cmd, t_options *options) {
	size_t		result_size;
	size_t		size;
	char		*query;
	char		*result;

	int fd = open(options->in, O_RDONLY);
	if (fd < 0)
	{
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->in, strerror(errno));
		return (1);
	}
	struct stat buf;
	if (fstat(fd, &buf) != 0) {
		close(fd);
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->in, strerror(errno));
		return (1);
	}
	if (S_ISDIR(buf.st_mode)) {
		close(fd);
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->in, "Is a directory");
		return (1);
	}
	if (!(query = read_query(fd, &size)))
	{
		close(fd);
		return (1);
	}
	result = launch_std(cmd, query, size, &result_size, options);
	if (!result) {
		free(query);
		close(fd);
		return (1);
	}
	print_std_result(result, result_size, cmd, options);
	free(query);
	free(result);
	close(fd);
	return (0);
}

int		process_std(t_ssl *ssl) {
	int				ret;
	t_options		options;

	memset(&options, 0, sizeof(t_options));
	ret = fill_std_options(&options, ssl);
	if (ret)
		return (ret);
	if (!options.in) {
		ret = process_std_stdin(ssl->cmd, &options);
	} else {
		ret = process_std_file(ssl->cmd, &options);
	}
	return (ret);
}
