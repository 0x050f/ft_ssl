#include "ft_ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE 32

// TODO: error
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
// TODO: error
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
		uint8_t *tmp = (uint8_t *)sha256(key, key_len);
		if (!tmp)
			return (NULL);
		hex2bytes((char *)tmp, k, SHA256_BLOCK_SIZE);
		free(tmp);
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
	hex2bytes((char *)ihash, tmp, SHA256_BLOCK_SIZE);
	free(ihash);
	ohash = h(k_opad, SHA256_BLOCK_SIZE, tmp, SHA256_HASH_SIZE); // hash(k_opad || ihash);
	if (!ohash)
		return (NULL);
	return (ohash);
}


/*
  RFC 8018
  default openssl -pbkdf2:  -iter 10000 -md sha256
  prf: pseudo-random-function (here sha256)
  p: password
  s: salt
  c: iteration count
  dklen: length of the derived key
*/
char	*pbkdf2(char *(prf(uint8_t *, int, uint8_t *, int)), char *p, uint64_t s, size_t c, size_t dklen)
{
	(void)prf;
	(void)s;
	(void)p;
	uint32_t t[2];
	size_t i;
	(void)i;

	{
		char key[] = "key";
		char msg[] = "The quick brown fox jumps over the lazy dog";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 1\n");
		char key[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
		char msg[] = "Hi There";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 2\n");
		char key[] = "Jefe";
		char msg[] = "what do ya want for nothing?";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 3\n");
		char key[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		char msg[] = "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 4\n");
		char key[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
		char msg[] = "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 5\n");
		char key[] = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
		char msg[] = "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61\x74\x69\x6f\x6e";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 6\n");
		char key[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		char msg[] = "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	{
		printf("Test case 7\n");
		char key[] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		char msg[] = "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e";
		char *digest = hmac_sha256((unsigned char *)msg, strlen(msg), (unsigned char *)key, strlen(key));
		printf("digest: %.64s\n", digest);
		free(digest);
	}
	exit(0);
	i = 0;
	memset(&t, 0, sizeof(uint32_t) * 2);
	(void)c;
	(void)dklen;
	/*
	size_t block_len = 0;
	while (block_len < dklen)
	{
		// F(P, S, c, i + 1)
		uint32_t u[c];
		for (size_t j = 0; j < c; j++) // U_{j + 1}
		{
			char *hash;
			if (!j) // PRF(P, S || INT(i + 1))
				hash = hmac_sha256(p, strlen(password), );// ??
			else // PRF(P, U_{j - 1})
				hash = hmac_sha256(p, strlen(password), u[j - 1], sizeof(uint32_t));
			u[j] = hex2int32(hash);
			free(hash);
		}
		for (size_t j = 0; j < c; j++)
			t[i] ^= u[j];
		block_len += sizeof(uint32_t);
		i++;
	}
	for (size_t i = 0; i < 2; i++)
		printf("t[%d]: %x", i, t[i]);
	*/
	return (NULL);
}

char		*launch_cipher(char *cmd, char *query, size_t size, size_t *res_len, t_options *options)
{
	char *cmds[NB_CIPHER_CMDS] = CMD_CIPHER;
	char *(*functions[NB_CIPHER_CMDS])(uint8_t *, size_t, size_t *, t_options *) = FUNC_CIPHER;

	for (int i = 0; i < NB_CIPHER_CMDS; i++)
	{
		if (!strcmp(cmd, cmds[i]))
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
	if (!strcmp(cmd, "base64"))
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

void		process_cipher_file(char *cmd, t_options *options)
{
	size_t		size;
	char		*query;
	char		*result;
	size_t		result_size;

	int fd = open(options->infile, O_RDONLY);
	if (fd < 0)
	{
		dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", PRG_NAME, cmd, options->infile, strerror(errno));
		return ;
	}
	if (!(query = read_query(fd, &size)))
	{
		close(fd);
		return ;
	}
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		return ;
	}
	print_cipher_result(result, result_size, cmd, options);
	free(query);
	free(result);
	close(fd);
}

void		process_cipher_stdin(char *cmd, t_options *options)
{
	size_t	size;
	char	*query;
	char	*result;
	size_t	result_size;

	if (!(query = read_query(STDIN_FILENO, &size)))
		return ;
	result = launch_cipher(cmd, query, size, &result_size, options);
	if (!result)
	{
		free(query);
		return ;
	}
	print_cipher_result(result, result_size, cmd, options);
	free(query);
	free(result);
}

int			fill_options(t_options *options, t_ssl *ssl)
{
	options->options = ssl->options;
	/* set options to the last arg recv */
	void *pos_d = strchr(ssl->options, 'd');
	void *pos_e = strchr(ssl->options, 'e');
	options->mode = (pos_e >= pos_d) ? CMODE_ENCODE : CMODE_DECODE;
	options->infile = get_last_content(ssl->opt_args, 'i');
	options->outfile = get_last_content(ssl->opt_args, 'o');
	options->key = get_last_content(ssl->opt_args, 'k');
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
		sprintf(msg, "Verifying - enter %s encryption password: ", ssl->cmd);
		tmp = getpass(msg);
		if (!tmp)
		{
			free(password);
			dprintf(STDERR_FILENO, "%s: %s: getpass: %s\n", PRG_NAME, ssl->cmd, strerror(errno));
			return (-1);
		}
		if (strcmp(tmp, password))
		{
			free(password);
			printf("Verify failure\n");
			dprintf(STDERR_FILENO, "bad password read\n");
			return (-2);
		}
		options->password = password;
	}
	else
		options->password = get_last_content(ssl->opt_args, 'p');
	options->salt = get_last_content(ssl->opt_args, 's');
	options->iv = get_last_content(ssl->opt_args, 'v');
	return (0);
}

void	process_cipher(t_ssl *ssl)
{
	size_t			result_len;
	t_options		options;

	(void)result_len;
	memset(&options, 0, sizeof(t_options));
	int ret = fill_options(&options, ssl);
	if (ret)
		return ;
	if (!strchr(ssl->options, 'i'))
		process_cipher_stdin(ssl->cmd, &options);
	else
		process_cipher_file(ssl->cmd, &options);
	free(options.password);
}
