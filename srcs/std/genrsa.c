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
			z = (z * (__int128_t)x) % p;
		}
		n /= 2;
		x = ((__int128_t)x * x) % p;
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
	if (x == 1 || x == n - 1)
		return (false);
	while (s-- > 0) {
		x = power_mod(x, 2, n);
		if (x == n - 1)
			return (false);
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
		if (miller(n, a))
			return (false);
	}
	return (true);
}

#include <math.h>

double		pow(double, double);

bool		check_prime(uint64_t n, double proba) {
	if (!(proba >= 0.0 && proba <= 1.0))
		return (false);

	double nb_round = 1.0;
	// miller-rabin: 75% chance on each round to detect a non-prime value
	while (pow(0.25, nb_round) > 1.0 - proba) {
		nb_round += 1;
	}
	return (miller_rabin(n, nb_round));
}

char		*genrsa(uint8_t *query, size_t size, size_t *res_len, t_options *options) {
	char	header[] = "-----BEGIN PRIVATE KEY-----\n";
	char	footer[] = "-----END PRIVATE KEY-----\n";
	char	*result;

	DPRINT("genrsa(\"%.*s\", %zu)\n", (int)size, query, size);
	*res_len = strlen(header) + strlen(footer) + 1;
	result = malloc(*res_len);
	memset(result, 0, *res_len);

	/* Solovay-Strassen < Miller-Rabin speed */

	uint64_t prime = custom_rand();
	while (!check_prime(prime, 1.0))
		prime = custom_rand();
	printf("%llu is prime\n", prime);


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
