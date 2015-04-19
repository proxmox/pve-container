#!/usr/bin/perl

use strict;
use warnings;
use PVE::Tools qw(run_command);

use lib qw(..);

use PVE::LXC;
use PVE::LXCSetup;

sub test_file {
    my ($exp_fn, $real_fn) = @_;

    return if system("diff '$exp_fn' '$real_fn'") == 0;

    die "files does not match\n";
}

sub run_test {
    my ($testdir) = @_;

    my $rootfs = "./tmprootfs";

    run_command("rm -rf $rootfs");
    run_command("cp -a $testdir $rootfs");
    
    my $config_fn = "$testdir/config";
    
    my $raw = PVE::Tools::file_get_contents($config_fn);

    my $conf = PVE::LXC::parse_lxc_config("/lxc/100/config", $raw);

    $conf->{'lxc.rootfs'} = $rootfs;
    
    my $lxc_setup = PVE::LXCSetup->new('debian', $conf);

    $lxc_setup->set_hostname();

    test_file("$testdir/etc/hostname.exp", "$rootfs/etc/hostname");
    test_file("$testdir/etc/hosts.exp", "$rootfs/etc/hosts");

    print "TEST $testdir => OK\n";
}

PVE::Tools::dir_glob_foreach('.', 'test\d+', sub {
    my ($testdir) = @_;
    run_test($testdir);     
});

exit(0);
