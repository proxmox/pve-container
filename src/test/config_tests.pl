#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::LXC::Config;

my sub create_conf {
    my ($common, $new, $old) = @_;

    my $new_str = defined($new) ? $common . ',' . $new : $common;
    my $old_str = defined($old) ? $common . ',' . $old : $common;
    return (
        PVE::LXC::Config->parse_volume('mp0', $new_str),
        PVE::LXC::Config->parse_volume('mp0', $old_str),
    );
}

subtest 'same config can be applied' => sub {
    my ($new, $old) = create_conf("local:100/vm-100-disk-1.raw,mp=/mnt,backup=1");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'config with only backup difference can be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw,mp=/mnt", "backup=1", "backup=0");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'fast plug option also ignored if previously not present' => sub {
    my ($new, $old) = create_conf("local:100/vm-100-disk-1.raw,mp=/mnt", "replicate=1", undef);
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'difference in mountpoint cannot be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw,replicate=1", "mp=/mnt/one", "mp=/mnt/two");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok(!$result, "cannot be hotplugged");
};

subtest 'changing fast pluggable and non fast pluggable cannot be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw", "mp=/mnt/one", "mp=/mnt/two,replicate=1");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok(!$result, "cannot be hotplugged");
};

subtest 'idmap array does not throw off comparison' => sub {
    my ($new, $old) = create_conf(
        "local:100/vm-100-disk-1.raw,mp=/mnt,idmap=u:0:100000:65536;g:0:100000:65536",
        "backup=1",
        undef,
    );
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

done_testing();
