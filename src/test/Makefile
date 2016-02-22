all:


test: test_setup test_snapshot

test_setup: run_setup_tests.pl
	./run_setup_tests.pl

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl

clean:
	rm -rf tmprootfs
