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
			z = (z * x) % p;
		}
		n /= 2;
		x = (x * x) % p;
	}
	return (z);
}

bool		miller(uint64_t n, uint64_t a) {
	int			s;
	uint64_t	d, x;

	printf("a: %zu\n", a);
	s = 0;
	d = n - 1;
	while (!(d % 2)) { // n - 1 = (2 ^ s) * d
		s++;
		d /= 2;
	}
	printf("%zu - 1 = (2 ^ %zu) * %zu\n", n, s, d);
	x = power_mod(a, d, n);
	printf("(%zu ^ %zu) %% %zu = %zu\n", a, d, n, x);
	if (x == 1 || x == n - 1) {
		printf("lol\n");
		return (false);
	}
	printf("s: %d\n", s);
	printf("x: %zu\n", x);
	while (--s > 0) {
		x = power_mod(x, 2, n);
		printf("x: %zu\n", x);
		if (x == n - 1)
			return (false);
	}
	printf("mais mdr\n");
	return (true);
}

// Return true if integer n is probably prime (n odd >= 3, k >= 1)
bool		miller_rabin(uint64_t n, size_t k) {
	uint64_t a;

	while (k--) {
		a = rand_range(2, n - 2);
		// random choose a between 2 and n - 2
		printf("lool\n");
		if (miller(n, a))
			return (false);
	}
	return (true);
}

char		*genrsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	char	header[] = "-----BEGIN PRIVATE KEY-----\n";
	char	footer[] = "-----END PRIVATE KEY-----\n";
	char	*result;

	DPRINT("genrsa(\"%.*s\", %zu)\n", (int)size, query, size);
	*res_len = strlen(header) + strlen(footer) + 1;
	result = malloc(*res_len);
	memset(result, 0, *res_len);

	bool ret = miller_rabin(87178291199, 1000000);
	if (ret) {
		printf("miller-rabin: true\n");
	} else {
		printf("miller-rabin: false\n");
	}

	/* Solovay-Strassen < Miller-Rabin speed */

	/* 1. choose two large prime numbers p and q */

	/* 2. compute n = pq */

	memcpy(result, header, strlen(header));
	memcpy(result + *res_len - (strlen(footer) + 1), footer, strlen(footer));
	(void)query;
	(void)size;
	(void)res_len;
	(void)options;
	return (result);
}
