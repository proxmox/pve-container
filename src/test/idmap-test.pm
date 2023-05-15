package PVE::LXC::Test;

use strict;
use warnings;

use lib qw(..);

use Test::More;
use Time::HiRes qw (gettimeofday tv_interval);

use PVE::LXC;

subtest 'valid: default config (unprivileged)' => sub {
    plan tests => 1;

    my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
	    unprivileged => 1,
	    lxc => [ ['rootfs', 'xyz'] ],
    });

    $@ = undef;
    eval {
	PVE::LXC::validate_id_maps($id_maps);
    };
    is($@, "", "no error");
};

subtest 'valid: mapping one user/group to host' => sub {
    plan tests => 1;

    my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
	    lxc => [
		['lxc.idmap', 'u 0 100000 1005'],
		['lxc.idmap', 'g 0 100000 1007'],
		['lxc.idmap', 'u 1005 1005 1'],
		['lxc.idmap', 'g 1007 1007 1'],
		['lxc.idmap', 'u 1006 101006 64530'],
		['lxc.idmap', 'g 1008 101008 64528'],
	    ],
    });

    $@ = undef;
    eval {
	PVE::LXC::validate_id_maps($id_maps);
    };
    is($@, "", "no error");
};

subtest 'valid: mapping user/group ranges to host' => sub {
    plan tests => 1;

    my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
	    lxc => [
		['lxc.idmap', 'u 3000 103000 60000'],
		['lxc.idmap', 'u 2000 1000 1000'],
		['lxc.idmap', 'u 0 100000 2000'],
		['lxc.idmap', 'g 2000 102000 63534'],
		['lxc.idmap', 'g 1000 2000 1000'],
		['lxc.idmap', 'g 0 100000 1000'],
		['lxc.idmap', 'u 63000 263000 2536'],
		['lxc.idmap', 'g 65534 365534 2'],
	    ],
    });

    $@ = undef;
    eval {
	PVE::LXC::validate_id_maps($id_maps);
    };
    is($@, "", "no error");
};

subtest 'invalid: ambiguous mappings' => sub {
    plan tests => 10;

    $@ = undef;
    eval {
	my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
		lxc => [
		    ['lxc.idmap', 'u 0 100000 1005'],
		    ['lxc.idmap', 'u 1005 1005 2'], # maps host uid 1005
		    ['lxc.idmap', 'u 1007 101007 992'],
		    ['lxc.idmap', 'u 11000 1000 10'], # maps host uid 1005 again
		],
	});
	PVE::LXC::validate_id_maps($id_maps);
    };
    like($@, qr/invalid map entry 'u 1005 1005 2'/, '$@ correct');
    like($@, qr/host uid 1005 is also mapped by entry 'u 11000 1000 10'/, '$@ correct');

    $@ = undef;
    eval {
	my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
		lxc => [
		    ['lxc.idmap', 'u 0 100000 65536'], # maps container uid 1005
		    ['lxc.idmap', 'u 1005 1005 1'], # maps container uid 1005 again
		    ['lxc.idmap', 'u 1006 201006 64530'],
		],
	});
	PVE::LXC::validate_id_maps($id_maps);
    };

    like($@, qr/invalid map entry 'u 1005 1005 1'/, '$@ correct');
    like($@, qr/container uid 1005 is also mapped by entry 'u 0 100000 65536'/, '$@ correct');

    $@ = undef;
    eval {
	my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
		lxc => [
		    ['lxc.idmap', 'u 5 100000 6'], # 5..10
		    ['lxc.idmap', 'u 0 200000 11'], # 0..10
		    ['lxc.idmap', 'u 3 300000 2'], # 3..4
		],
	});
	PVE::LXC::validate_id_maps($id_maps);
    };

    # this flags line 2 and 3. the input is [ 0..10, 3..4, 5..10 ], and the
    # algorithm misses the conflict between 0..10 and 5..10.
    like($@, qr/invalid map entry 'u 3 300000 2'/, '$@ correct');
    like($@, qr/container uid 3 is also mapped by entry 'u 0 200000 11'/, '$@ correct');

    $@ = undef;
    eval {
	my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
		lxc => [
		    ['lxc.idmap', 'g 0 100000 1001'], # maps container gid 1000
		    ['lxc.idmap', 'g 1000 1000 10'], # maps container gid 1000 again
		],
	});
	PVE::LXC::validate_id_maps($id_maps);
    };
    like($@, qr/invalid map entry 'g 1000 1000 10'/, '$@ correct');
    like($@, qr/container gid 1000 is also mapped by entry 'g 0 100000 1001'/, '$@ correct');

    $@ = undef;
    eval {
	my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({
		lxc => [
		    ['lxc.idmap', 'g 0 100000 1000'], # maps host gid 100000
		    ['lxc.idmap', 'g 2000 102000 1000'],
		    ['lxc.idmap', 'g 3500 99500 5000'], # maps host gid 100000 again
		],
	});
	PVE::LXC::validate_id_maps($id_maps);
    };
    like($@, qr/invalid map entry 'g 0 100000 1000'/, '$@ correct');
    like($@, qr/host gid 100000 is also mapped by entry 'g 3500 99500 5000'/, '$@ correct');
};

subtest 'check performance' => sub {
    plan tests => 1;

    # generate mapping with 1000 entries
    my $entries = [];
    foreach my $i (0..999) {
	my $first_container_uid = $i * 10;
	my $first_host_uid = 100000 + $first_container_uid;
	push @$entries, ['lxc.idmap', "u $first_container_uid $first_host_uid 10"]
    }

    my ($id_maps, undef, undef) = PVE::LXC::parse_id_maps({ lxc => $entries });

    my $start_time = [ gettimeofday() ];
    $@ = undef;
    eval {
	PVE::LXC::validate_id_maps($id_maps);
    };
    my $elapsed = tv_interval($start_time);

    is($@, "", "no error");
    diag("validation took $elapsed seconds");
};

done_testing();
