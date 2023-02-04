#include "ft_ssl.h"
#include "cipher.h"
#include "hash.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE 32

// hash(text || key)
char	*h(unsigned char *text, int text_len, uint8_t *key, int key_len)
{
	size_t		buflen = text_len + key_len;
	uint8_t		*buf = malloc(buflen);

	if (!buf)
		return (NULL);
	memcpy(buf, text, text_len);
	memcpy(buf + text_len, key, key_len);
	char *ret = sha256(buf, buflen);
	free(buf);
	return (ret);
}

/*
  RFC 2104
  https://en.wikipedia.org/wiki/HMAC
*/
char		*hmac_sha256(uint8_t *text, int text_len, uint8_t *key, int key_len)
{
	uint8_t		k[SHA256_BLOCK_SIZE];
	uint8_t		k_ipad[SHA256_BLOCK_SIZE];
	uint8_t		k_opad[SHA256_BLOCK_SIZE];
	uint8_t		tmp[SHA256_HASH_SIZE];
	char		*ihash;
	char		*ohash;

	/* Compute the block_size key */
	memset(k, 0, SHA256_BLOCK_SIZE);
	/* start out by storing key in pads */
	memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
	memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
	if (key_len > SHA256_BLOCK_SIZE) /* key = hash(key) */
	{
		uint8_t *digest = (uint8_t *)sha256(key, key_len);
		if (!digest)
			return (NULL);
		hex2bytes(k, SHA256_BLOCK_SIZE, (char *)digest);
		free(digest);
	}
	else /* pad key */
		memcpy(k, key, key_len);
	/* XOR key with ipad and opad values */
	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		k_ipad[i] ^= k[i]; // outer padded key
		k_opad[i] ^= k[i]; // inner padded key
	}
	/* HMAC */
	// hash(o_key_pad || hash(i_key_pad || message))
	ihash = h(k_ipad, SHA256_BLOCK_SIZE, text, text_len); // hash(k_ipad || text)
	if (!ihash)
		return (NULL);
	 /* translate to 32 bytes non-ascii */
	hex2bytes(tmp, SHA256_BLOCK_SIZE, (char *)ihash);
	free(ihash);
	ohash = h(k_opad, SHA256_BLOCK_SIZE, tmp, SHA256_HASH_SIZE); // hash(k_opad || ihash);
	if (!ohash)
		return (NULL);
	return (ohash);
}

#define HLEN 32 // output of sha256 in bits

/*
  RFC 8018
  default openssl -pbkdf2:  -iter 10000 -md sha256
  prf: pseudo-random-function (here sha256)
  p: password
  s: salt
  c: iteration count
  dklen: length of the derived key
*/
uint8_t		*pbkdf2(char *(prf(uint8_t *, int, uint8_t *, int)), char *p, size_t psize, char *s, size_t ssize, size_t c, size_t dklen)
{
	if (dklen > 4294967295 * HLEN) // dklen > (2 ^ 32 - 1) * hlen
	{
		dprintf(STDERR_FILENO, "derived key too long\n");
		return (NULL);
	}
	int l = ceil((float)dklen / (float)HLEN); // bytes in block - ceil
	int r = dklen - (l - 1) * HLEN; // bytes in last block
	
	uint8_t t[l][HLEN];
	for (size_t i = 0; i < (size_t)l; i++)
		memset(t[i], 0, HLEN);
	// F(P, S, c, i)
	for (size_t i = 1; i <= (size_t)l; i++)
	{
		uint8_t u[HLEN];
		// U_j = PRF (P, u_{j-1})
		for (size_t j = 1; j <= c; j++)
		{
			char *hash;
			if (j == 1)
			{
				uint8_t		tmp[ssize + sizeof(int)];
				memcpy(tmp, s, ssize);
				b_memcpy(tmp + ssize, &i, sizeof(int));
				hash = prf(tmp, ssize + sizeof(int), (uint8_t *)p, psize);
			}
			else
				hash = prf(u, HLEN, (uint8_t *)p, psize);
			if (!hash)
				return (NULL);
			hex2bytes(u, HLEN, hash);
			free(hash);
			for (size_t k = 0; k < HLEN; k++)
				t[i - 1][k] ^= u[k];
		}
	}
	uint8_t *ret = malloc(dklen);
	if (!ret)
		return (NULL);
	size_t n = 0;
	for (size_t i = 0; i < (size_t)l; i++)
	{
		for (size_t j = 0; j < HLEN && (i != (size_t)l - 1 || j < (size_t)r); j++)
			ret[n++] = t[i][j];
	}
	return (ret);
}

char		*launch_cipher(char *cmd, char *query, size_t size, size_t *res_len, t_options *options)
{
	char *cmds[NB_CIPHER_CMDS][2] = CMD_CIPHER;
	char *(*functions[NB_CIPHER_CMDS])(uint8_t *, size_t, size_t *, t_options *) = FUNC_CIPHER;

	for (int i = 0; i < NB_CIPHER_CMDS; i++)
	{
		if (!strcmp(cmd, cmds[i][0]))
			return (functions[i]((unsigned char *)query, size, res_len, options));
	}
	return (NULL);
}

void		print_cipher_result(char *result, size_t result_size, char *cmd, t_options *options)
{
	if (!result_size)
		return ;
	int fd = STDOUT_FILENO;
	if (options->outfile)
	{
		fd = open(options->outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0)
		{
			dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->outfile, strerror(errno));
			return ;
		}
	}
	if ((!strcmp(cmd, "base64") || options->base64) && options->mode == CMODE_ENCODE)
	{
		char *tmp = result;
		while (result_size > 64)
		{
			write(fd, tmp, 64);
			write(fd, "\n", 1);
			tmp += 64;
			result_size -= 64;
		}
		write(fd, tmp, result_size);
		write(fd, "\n", 1);
	}
	else
		write(fd, result, result_size);
	if (options->outfile)
		close(fd);
}

int			process_cipher_file(char *cmd, t_options *options)
{
	size_t		size;
	char		*query;
	char		*result;
	size_t		result_size;

	int fd = open(options->infile, O_RDONLY);
	if (fd < 0)
	{
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->infile, strerror(errno));
		return (1);
	}
	struct stat buf;
	if (fstat(fd, &buf) != 0) {
		close(fd);
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->infile, strerror(errno));
		return (1);
	}
	if (S_ISDIR(buf.st_mode)) {
		close(fd);
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->infile, "Is a directory");
		return (1);
	}
	if (!(query = read_query(fd, &size)))
	{
		close(fd);
		return (1);
	}
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		close(fd);
		return (1);
	}
	print_cipher_result(result, result_size, cmd, options);
	free(query);
	free(result);
	close(fd);
	return (0);
}

int			process_cipher_stdin(char *cmd, t_options *options)
{
	size_t	size;
	char	*query;
	char	*result;
	size_t	result_size;

	if (!(query = read_query(STDIN_FILENO, &size)))
		return (1);
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		return (1);
	}
	print_cipher_result(result, result_size, cmd, options);
	free(query);
	free(result);
	return (0);
}

int			fill_cipher_options(t_options *options, t_ssl *ssl)
{
	/* set options to the last arg recv */
	t_opt_arg *arg = get_last_arg(ssl->opt_args, "d");
	int pos_d = arg ? arg->index : -1;
	arg = get_last_arg(ssl->opt_args, "e");
	int pos_e = arg ? arg->index : -1;
	options->mode = (pos_e >= pos_d) ? CMODE_ENCODE : CMODE_DECODE;
	options->base64 = get_last_arg(ssl->opt_args, "a") ? true : false;
	options->infile = get_last_content(ssl->opt_args, "i");
	options->outfile = get_last_content(ssl->opt_args, "o");
	options->key = get_last_content(ssl->opt_args, "k");
	arg = get_last_arg(ssl->opt_args, "t");
	options->iter = arg ? atoi(arg->content) : 10000;
	if (options->iter < 0 || options->iter > 10000) {
		return (args_error(ERR_OOR_ARG, "-t", 0, 10000));
	}
	char *tmp;
	if ((tmp = get_last_content(ssl->opt_args, "p")))
	{
		options->password = strdup(tmp);
		if (!options->password)
			return(ERR_MALLOC);
	}
	if (!options->key && !options->password && strcmp(ssl->cmd, "base64"))
	{
		char msg[256];

		sprintf(msg, "enter %s encryption password: ", ssl->cmd);
		char *tmp = getpass(msg);
		if (!tmp)
		{
			dprintf(STDERR_FILENO, "%s: %s: getpass: %s\n", PRG_NAME, ssl->cmd, strerror(errno));
			return (-1);
		}
		char *password = strdup(tmp);
		if (!password)
		{
			dprintf(STDERR_FILENO, "%s: malloc error\n", PRG_NAME);
			return (ERR_MALLOC);
		}
		if (options->mode == CMODE_ENCODE) // Don't verify password in decode mode
		{
			//TODO: ask password when verifying header ?
			sprintf(msg, "Verifying - enter %s encryption password: ", ssl->cmd);
			tmp = getpass(msg);
			if (!tmp)
			{
				free(password);
				dprintf(STDERR_FILENO, "%s: %s: getpass: %s\n", PRG_NAME, ssl->cmd, strerror(errno));
				return (1);
			}
			if (strcmp(tmp, password))
			{
				free(password);
				printf("Verify failure\n");
				dprintf(STDERR_FILENO, "bad password read\n");
				return (2);
			}
		}
		options->password = password;
	}
	options->salt = get_last_content(ssl->opt_args, "s");
	options->iv = get_last_content(ssl->opt_args, "v");
	return (0);
}

int		process_cipher(t_ssl *ssl)
{
	int				ret;
	t_options		options;

	memset(&options, 0, sizeof(t_options));
	ret = fill_cipher_options(&options, ssl);
	if (ret)
		return (ret);
	if (!get_last_arg(ssl->opt_args, "i"))
		ret = process_cipher_stdin(ssl->cmd, &options);
	else
		ret = process_cipher_file(ssl->cmd, &options);
	free(options.password);
	return (ret);
}
