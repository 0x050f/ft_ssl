#include "tests.h"

int		main(void)
{
	int no_failed = 0;
	Suite *s;
	SRunner *runner;

	s = test_hmac_sha256();
	runner = srunner_create(s);

	srunner_run_all(runner, CK_NORMAL);
	no_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (no_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
