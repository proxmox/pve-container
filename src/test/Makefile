RUN_USERNS := lxc-usernsexec -m "u:0:`id -u`:1" -m "g:0:`id -g`:1" --

all: test

test: test_setup test_snapshot test_bindmount test_idmap

test_setup: run_setup_tests.pl
	if test -e /run/lock/sbuild; then \
		echo skipping userns tests in sbuild environment ; \
	else \
		$(RUN_USERNS) ./run_setup_tests.pl ; \
	fi

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl

test_bindmount: bindmount_test.pl
	if test -e /run/lock/sbuild; then \
		echo skipping userns tests in sbuild environment ; \
	else \
		$(RUN_USERNS) ./bindmount_test.pl ; \
	fi

test_idmap: run_idmap_tests.pl
	./run_idmap_tests.pl

clean:
	rm -rf tmprootfs
