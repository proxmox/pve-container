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

    $conf->{'pve.test_mode'} = 1;
    
    my $lxc_setup = PVE::LXCSetup->new($conf, $rootfs);

    for (my $i = 0; $i < 2; $i++) {
	# run tests twice, to make sure scripts are idempotent
	
	$lxc_setup->post_create_hook('$TEST$ABCDEF');

	my @testfiles = qw(/etc/hostname /etc/hosts /etc/inittab /etc/network/interfaces /etc/resolv.conf /etc/passwd /etc/shadow /etc/sysconfig/network /etc/sysconfig/network-scripts/ifcfg-eth0 /etc/sysconfig/network-scripts/ifcfg-eth1 /etc/sysconfig/network-scripts/ifcfg-eth2 /etc/sysconfig/network-scripts/ifcfg-eth3 /etc/init/start-ttys.conf /etc/init/tty.conf);
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

    foreach my $testdir (<test-*>) {#
	next if ! -d $testdir; 
	run_test($testdir);
    }
}

exit(0);
