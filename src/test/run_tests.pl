#!/usr/bin/perl

use strict;
use warnings;
use PVE::Tools qw(run_command);

use lib qw(..);

use PVE::LXC;
use PVE::LXCSetup;

sub test_file {
    my ($exp_fn, $real_fn) = @_;

    return if system("diff -u '$exp_fn' '$real_fn'") == 0;

    die "files does not match\n";
}

sub run_test {
    my ($testdir) = @_;

    print "prepare $testdir\n";
    
    my $rootfs = "./tmprootfs";

    run_command("rm -rf $rootfs");
    run_command("cp -a $testdir $rootfs");
    
    my $config_fn = "$testdir/config";
    
    my $raw = PVE::Tools::file_get_contents($config_fn);

    my $conf = PVE::LXC::parse_lxc_config("/lxc/100/config", $raw);

    $conf->{'lxc.rootfs'} = $rootfs;
    
    my $lxc_setup = PVE::LXCSetup->new($conf);

    for (my $i = 0; $i < 2; $i++) {
	# run tests twice, to make sure scripts are idempotent
	
	$lxc_setup->post_create_hook();

	my @testfiles = qw(/etc/hostname /etc/hosts /etc/inittab /etc/network/interfaces);
	foreach my $fn (@testfiles) {
	    next if !-f "$testdir/$fn.exp";
	    test_file("$testdir/$fn.exp", "$rootfs/$fn");
	}
    }
    
    print "TEST $testdir => OK\n";
}

if (scalar(@ARGV)) {

    foreach my $testdir (@ARGV) {
	run_test($testdir);  
    }

} else {

    PVE::Tools::dir_glob_foreach('.', 'test\d+', sub {
	my ($testdir) = @_;
	run_test($testdir);     
    });
}

exit(0);
