#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::LXC::Config;

# Creates new and old configurations based on the common core and just
# the changes. The fourth parameter can change the kind of mountpoint it
# is, instead of always using mp0.
my sub create_conf {
    my ($common, $new, $old, $mountpoint_name) = @_;

    $mountpoint_name //= 'mp0';

    my $new_str = defined($new) ? $common . ',' . $new : $common;
    my $old_str = defined($old) ? $common . ',' . $old : $common;
    return (
        PVE::LXC::Config->parse_volume($mountpoint_name, $new_str),
        PVE::LXC::Config->parse_volume($mountpoint_name, $old_str),
    );
}

subtest 'same config can be applied' => sub {
    my ($new, $old) = create_conf("local:100/vm-100-disk-1.raw,mp=/mnt,backup=1");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'rootfs same config can be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw,replicate=1", undef, undef, "rootfs");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'config with only backup difference can be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw,mp=/mnt", "backup=1", "backup=0");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'rootfs config with only replicate difference can be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw", "replicate=1", "replicate=0", "rootfs");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'fast plug option also ignored if previously not present' => sub {
    my ($new, $old) = create_conf("local:100/vm-100-disk-1.raw,mp=/mnt", "replicate=1", undef);
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'rootfs fast plug option also ignored if previously not present' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw", "replicate=1", undef, "rootfs");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'difference in mountpoint cannot be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw,replicate=1", "mp=/mnt/one", "mp=/mnt/two");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok(!$result, "cannot be hotplugged");
};

subtest 'rootfs difference in acl cannot be applied' => sub {
    my ($new, $old) = create_conf(
        "local:100/vm-100-disk-1.raw,replicate=1", "acl=0", "acl=1", "rootfs",
    );
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

    ok(!$result, "cannot be hotplugged");
};

subtest 'changing fast pluggable and non fast pluggable cannot be applied' => sub {
    my ($new, $old) =
        create_conf("local:100/vm-100-disk-1.raw", "mp=/mnt/one", "mp=/mnt/two,replicate=1");
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("mp0", $new, $old);

    ok(!$result, "cannot be hotplugged");
};

subtest 'rootfs changing fast pluggable and non fast pluggable cannot be applied' => sub {
    my ($new, $old) = create_conf(
        "local:100/vm-100-disk-1.raw", "acl=0", "acl=1,replicate=1", "rootfs",
    );
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

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

subtest 'rootfs idmap array does not throw off comparison' => sub {
    my ($new, $old) = create_conf(
        "local:100/vm-100-disk-1.raw,idmap=u:0:100000:65536;g:0:100000:65536",
        "replicate=1",
        undef,
        "rootfs",
    );
    my $result = PVE::LXC::Config->__mountpoint_config_fast_plug_safe("rootfs", $new, $old);

    ok($result, "can be hotplugged");
};

subtest 'parsing drops keys outside of the schema' => sub {
    my $raw = <<~'EOF';
        hostname: ct100
        net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:00,type=veth
        net01: name=eth1,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,type=veth
        net32: name=eth2,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,type=veth
        dev256: /dev/null
        unknown: value
        memory: invalid
        EOF

    my $conf;
    {
        local $SIG{__WARN__} = sub { };
        $conf = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw);
    }

    is($conf->{hostname}, 'ct100', 'valid key is kept');
    ok(defined($conf->{net0}), 'valid network device key is kept');
    ok(!exists($conf->{$_}), "unknown key $_ is dropped") for qw(net01 net32 dev256 unknown);
    is($conf->{memory}, 'invalid', 'invalid value of a known key is kept');
};

done_testing();
