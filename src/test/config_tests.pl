#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::RPCEnvironment;

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

subtest 'a value with a null character is not written' => sub {
    my $conf;
    {
        local $SIG{__WARN__} = sub { };
        $conf = PVE::LXC::Config::parse_pct_config(
            '/lxc/100.conf',
            "hostname: bad\0name\nmemory: 512\n",
        );
    }
    is($conf->{hostname}, "bad\0name", 'parsing keeps the value');

    eval { PVE::LXC::Config::write_pct_config('/lxc/100.conf', $conf) };
    like($@, qr/^detected invalid null character inside property 'hostname'$/, 'writing fails');
};

subtest 'restore does not take over pending changes of the backup' => sub {
    my $rpcenv = PVE::RPCEnvironment->init('cli');

    my $raw =
        "arch: amd64\nhostname: ct100\nmemory: 512\nostype: debian\nunprivileged: 1\n"
        . "\n[pve:pending]\nlxc.apparmor.profile: unconfined\nmemory: 4096\n"
        . "mp0: /etc,mp=/mnt/hostetc\n";
    my $backup = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw);
    ok(scalar(keys $backup->{pending}->%*), 'backup config has pending changes');

    for my $user ('user@pve', 'root@pam') {
        $rpcenv->set_user($user);
        for my $conf ({}, { pending => {} }) {
            my $what =
                "$user, " . (exists($conf->{pending}) ? 'with' : 'without') . ' own pending';
            PVE::LXC::Create::sanitize_and_merge_config($conf, $backup, $user ne 'root@pam', 0);
            is($conf->{memory}, 512, "$what: current values are taken over");
            ok(!scalar(keys(($conf->{pending} // {})->%*)), "$what: pending changes are not");
        }
    }
};

subtest 'restore adds missing MAC addresses of the backup' => sub {
    PVE::RPCEnvironment::get()->set_user('root@pam');

    my $cluster_module = Test::MockModule->new('PVE::Cluster');
    $cluster_module->mock(
        cfs_read_file => sub {
            my ($filename) = @_;
            die "unexpected read of $filename\n" if $filename ne 'datacenter.cfg';
            return { mac_prefix => 'BC:24:11' };
        },
    );

    my $with_hwaddr = 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,type=veth';
    my $raw = "hostname: ct100\nnet0: $with_hwaddr\nnet1: name=eth1,bridge=vmbr0,type=veth\n";
    my $backup = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw);

    my $conf = {};
    PVE::LXC::Create::sanitize_and_merge_config($conf, $backup, 0, 0);
    is($conf->{net0}, $with_hwaddr, 'MAC address of the backup is kept');
    my $net1 = PVE::LXC::Config->parse_lxc_network($conf->{net1}, 1);
    like($net1->{hwaddr}, qr/^BC:24:11(?::[0-9A-F]{2}){3}$/i, 'missing MAC address is added');
};

subtest 'meta property' => sub {
    like(PVE::LXC::Config->new_meta_info_string(), qr/^ctime=\d+$/, 'creation time is set');

    my $raw = "hostname: ct100\nmeta: ctime=1700000000\n";
    my $conf = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw, 1);
    is($conf->{meta}, 'ctime=1700000000', 'meta is parsed');
    is(PVE::LXC::Config::write_pct_config('/lxc/100.conf', $conf), $raw, 'meta is written');

    $raw = "hostname: ct100\nmeta: ctime=1700000000,unknown=value\n";
    my $warnings = '';
    {
        local $SIG{__WARN__} = sub { $warnings .= $_[0] };
        $conf = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw);
    }
    like($warnings, qr/unable to parse value of 'meta'/, 'unknown member causes a warning');
    is($conf->{meta}, 'ctime=1700000000,unknown=value', 'meta with unknown member is kept');
    eval { PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw, 1) };
    like($@, qr/unable to parse value of 'meta'/, 'unknown member fails strict parsing');

    ok(!exists(PVE::LXC::Config->json_config_properties({})->{meta}), 'meta cannot be set');
};

subtest 'missing MAC addresses of network devices are added' => sub {
    my $cluster_module = Test::MockModule->new('PVE::Cluster');
    $cluster_module->mock(
        cfs_read_file => sub {
            my ($filename) = @_;
            die "unexpected read of $filename\n" if $filename ne 'datacenter.cfg';
            return { mac_prefix => 'BC:24:11' };
        },
    );

    my $with_hwaddr = 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,type=veth';
    my $conf = {
        hostname => 'ct100',
        net0 => $with_hwaddr,
        net1 => 'name=eth1,bridge=vmbr0,type=veth',
    };

    ok(PVE::LXC::Config->add_missing_hwaddrs($conf), 'reports the added MAC address');
    is($conf->{net0}, $with_hwaddr, 'existing MAC address is kept');
    my $net1 = PVE::LXC::Config->parse_lxc_network($conf->{net1}, 1);
    like($net1->{hwaddr}, qr/^BC:24:11(?::[0-9A-F]{2}){3}$/i, 'MAC address uses the prefix');
    is($net1->{name}, 'eth1', 'other properties are kept');
    is($conf->{hostname}, 'ct100', 'other options are kept');

    my $net1_string = $conf->{net1};
    ok(!PVE::LXC::Config->add_missing_hwaddrs($conf), 'reports nothing if all are set');
    is($conf->{net1}, $net1_string, 'added MAC address stays');

    $conf->{net2} = 'name=eth2,bridge=vmbr0,unknown-property=1';
    $conf->{net3} = '0';
    $conf->{net4} = 'name=eth4,bridge=vmbr0';
    ok(
        PVE::LXC::Config->add_missing_hwaddrs($conf),
        'reports the MAC address after invalid ones',
    );
    is($conf->{net2}, 'name=eth2,bridge=vmbr0,unknown-property=1', 'invalid device is kept');
    is($conf->{net3}, '0', 'empty device is kept');
    ok(PVE::LXC::Config->parse_lxc_network($conf->{net4}, 1)->{hwaddr},
        'valid device gets one');
};

done_testing();
