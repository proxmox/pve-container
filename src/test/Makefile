RUN_USERNS := lxc-usernsexec -m "u:0:`id -u`:1" -m "g:0:`id -g`:1" --

all: test

test: test_setup test_snapshot test_bindmount

test_setup: run_setup_tests.pl
	$(RUN_USERNS) ./run_setup_tests.pl

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl

test_bindmount: bindmount_test.pl
	$(RUN_USERNS) ./bindmount_test.pl

clean:
	rm -rf tmprootfs
