#!/usr/bin/perl

use strict;
use warnings;

use Test::MockModule;

use PVE::Tools qw(run_command);

use lib qw(..);

use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Setup;

sub test_file {
    my ($exp_fn, $real_fn) = @_;

    # replace @DAYS@ with the current correct value
    if ($exp_fn =~ m/shadow.exp$/) {
	my $expecteddays = int(time()/(60*60*24));
	system ("sed -i.bak 's/\@DAYS\@/$expecteddays/' $exp_fn");
	my $ret = system("diff -u '$exp_fn' '$real_fn'");
	system("mv '$exp_fn.bak' '$exp_fn'");
	return if $ret == 0;
    } else {
	return if system("diff -u '$exp_fn' '$real_fn'") == 0;
    }

    die "files do not match\n";
}

sub run_test {
    my ($testdir) = @_;

    print "prepare $testdir\n";
    
    my $rootfs = "./tmprootfs";

    run_command("rm -rf $rootfs");
    run_command("cp -a $testdir $rootfs");
    
    my $config_fn = "$testdir/config";
    
    my $raw = PVE::Tools::file_get_contents($config_fn);

    my $conf = PVE::LXC::Config::parse_pct_config("/lxc/100.conf", $raw);

    $conf->{'testmode'} = 1;
    
    my $lxc_setup = PVE::LXC::Setup->new($conf, $rootfs);

    for (my $i = 0; $i < 2; $i++) {
	# run tests twice, to make sure scripts are idempotent
	
	srand(0);
	$lxc_setup->post_create_hook('$5$SALT$PASS','ssh-rsa ABCDEFG ABC@DEF');

	my @testfiles = qw(
	    /etc/hostname
	   /etc/hosts
	   /etc/inittab
	   /etc/locale.conf
	   /etc/network/interfaces
	   /etc/resolv.conf
	   /etc/passwd
	   /etc/shadow
	   /etc/sysconfig/network
	   /etc/sysconfig/network-scripts/ifcfg-eth0
	   /etc/sysconfig/network-scripts/route-eth0
	   /etc/sysconfig/network-scripts/route6-eth0
	   /etc/sysconfig/network-scripts/ifcfg-eth1
	   /etc/sysconfig/network-scripts/route-eth1
	   /etc/sysconfig/network-scripts/route6-eth1
	   /etc/sysconfig/network-scripts/ifcfg-eth2
	   /etc/sysconfig/network-scripts/route-eth2
	   /etc/sysconfig/network-scripts/route6-eth2
	   /etc/sysconfig/network-scripts/ifcfg-eth3
	   /etc/sysconfig/network-scripts/route-eth3
	   /etc/sysconfig/network-scripts/route6-eth3
	   /etc/sysconfig/network/ifcfg-eth0
	   /etc/sysconfig/network/ifroute-eth0
	   /etc/sysconfig/network/ifcfg-eth1
	   /etc/sysconfig/network/ifroute-eth1
	   /etc/sysconfig/network/ifcfg-eth2
	   /etc/sysconfig/network/ifroute-eth2
	   /etc/sysconfig/network/ifcfg-eth3
	   /etc/sysconfig/network/ifroute-eth3
	   /etc/systemd/system-preset/00-pve.preset
	   /etc/init/start-ttys.conf
	   /etc/init/tty.conf
	   /etc/init/power-status-changed.conf
	   /etc/securetty
	   /etc/crontab
	   /root
	   /root/.ssh
	   /root/.ssh/authorized_keys
	   /roothome
	   /roothome/.ssh
	   /roothome/.ssh/authorized_keys
	);
	for my $fn (@testfiles) {
	    next if !-f "$testdir/$fn.exp";
	    test_file("$testdir/$fn.exp", "$rootfs/$fn");
	}
    }
    
    print "TEST $testdir => OK\n";
}

my $cluster_module = Test::MockModule->new("PVE::Cluster");
$cluster_module->mock(
    cfs_read_file => sub {
	my ($filename) = @_;
	return {} if $filename eq 'datacenter.cfg';
	die "illegal access to pmxcfs in test!\n";
    },
    cfs_write_file => sub {
	die "illegal access to pmxcfs in test!\n";
    },
    cfs_lock_file => sub {
	die "illegal access to pmxcfs in test!\n";
    },
);


my $uuid_module = Test::MockModule->new("UUID");
$uuid_module->mock(
    uuid => sub {
	return '00000000-0000-0000-0000-000000000000';
    },
);

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
