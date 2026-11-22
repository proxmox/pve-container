#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::API2::LXC::Config;
use PVE::JSONSchema;
use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::LXC::Migrate;
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

subtest 'runtime env validation' => sub {
    my @valid = (
        'FOO=bar',
        'FOO=',
        "FOO=bar\0BAZ=1\t2",
        'LD_LIBRARY_PATH=/opt/lib',
        'TMPDIR=/tmp',
        'GLIBC_TUNABLES=glibc.malloc.check=1',
    );
    for my $val (@valid) {
        eval { PVE::JSONSchema::check_format('pve-lxc-env', $val) };
        is($@, '', "valid env passes check_format");
    }

    my @invalid = (
        [' LD_PRELOAD=/evil.so', qr/invalid environment variable entry/],
        [' FOO=bar', qr/invalid environment variable entry/],
        ['LD_PRELOAD', qr/invalid environment variable entry/],
        ['FOO', qr/invalid environment variable entry/],
        ['', qr/invalid empty property 'env'/],
        ["FOO=1\0", qr/invalid environment variable entry/],
        ["FOO=1\0\0BAR=2", qr/invalid environment variable entry/],
        ["FOO=1\nBAR=2", qr/invalid environment variable entry/],
    );
    for my $case (@invalid) {
        my ($val, $err_re) = @$case;
        eval { PVE::JSONSchema::check_format('pve-lxc-env', $val) };
        like($@, $err_re, "malformed env is rejected by check_format");
    }

    my $storage_mock = Test::MockModule->new('PVE::Storage');
    $storage_mock->mock(config => sub { return {}; });

    my $conf = {};
    eval {
        PVE::LXC::Config->queue_pct_config_changes(
            100,
            $conf,
            { env => "FOO=1\0HOSTVAR" },
            [],
            [],
        );
    };
    like(
        $@,
        qr/invalid environment variable entry 'HOSTVAR'/,
        'queue_pct_config_changes rejects malformed env',
    );
    ok(!exists($conf->{pending}->{env}), 'rejected env is not queued as pending');

    $conf = {};
    eval {
        PVE::LXC::Config->queue_pct_config_changes(
            100,
            $conf,
            { env => "FOO=1\0TMPDIR=/tmp" },
            [],
            [],
        );
    };
    is($@, '', 'queue_pct_config_changes accepts syntactically valid env');
    is(
        $conf->{pending}->{env},
        "FOO=1\0TMPDIR=/tmp",
        'syntactically valid env is queued as pending',
    );

    my $rpcenv = eval { PVE::RPCEnvironment->init('cli') } || PVE::RPCEnvironment->get();
    my $rpc_mock = Test::MockModule->new('PVE::RPCEnvironment');
    $rpc_mock->mock(check_vm_perm => sub { return 1; });

    for my $var (
        'LD_PRELOAD=/ok.so',
        'LD_LIBRARY_PATH=/opt/lib',
        'GLIBC_TUNABLES=glibc.malloc.check=1',
        'TMPDIR=/tmp',
    ) {
        eval {
            PVE::LXC::check_ct_modify_config_perm(
                $rpcenv,
                'root@pam',
                100,
                undef,
                {},
                { env => $var },
                [],
                1,
            );
        };
        is($@, '', "root\@pam is allowed to set $var");

        for my $user ('user@pve', 'root@pam!tok') {
            eval {
                PVE::LXC::check_ct_modify_config_perm(
                    $rpcenv,
                    $user,
                    100,
                    undef,
                    {},
                    { env => "FOO=1\0$var" },
                    [],
                    1,
                );
            };
            like(
                $@,
                qr/setting restricted environment variable '(?:LD_PRELOAD|LD_LIBRARY_PATH|GLIBC_TUNABLES|TMPDIR)' is only allowed for root\@pam/,
                "$user cannot set $var",
            );
        }
    }

    eval {
        PVE::LXC::check_ct_modify_config_perm(
            $rpcenv,
            'user@pve',
            100,
            undef,
            {},
            { env => "FOO=1\0BAR=2" },
            [],
            1,
        );
    };
    is($@, '', 'user@pve can set unrestricted env vars');

    eval {
        PVE::LXC::check_ct_modify_config_perm(
            $rpcenv,
            'user@pve',
            100,
            undef,
            { env => 'LD_PRELOAD=/ok.so' },
            {},
            ['env'],
            1,
        );
    };
    is($@, '', 'user@pve with VM.Config.Options can delete env');
};

subtest 'existing configs and snapshots with restricted env vars can still be written' => sub {
    my $raw = <<~'EOF';
        hostname: ct100
        lxc.environment.runtime: LD_LIBRARY_PATH=/opt/lib

        [snap1]
        hostname: ct100
        lxc.environment.runtime: TMPDIR=/app/tmp
        EOF
    my $conf = PVE::LXC::Config::parse_pct_config('/lxc/100.conf', $raw, 1);
    is($conf->{env}, 'LD_LIBRARY_PATH=/opt/lib', 'current restricted env is parsed');
    is(
        $conf->{snapshots}->{snap1}->{env},
        'TMPDIR=/app/tmp',
        'snapshot restricted env is parsed',
    );

    my $written = eval { PVE::LXC::Config::write_pct_config('/lxc/100.conf', $conf) };
    is(
        $@,
        '',
        'write_pct_config succeeds for existing config and snapshot with restricted env',
    );
    is($written, $raw, 'write_pct_config preserves existing restricted env entries');
};

subtest 'GET config schema accepts legacy malformed env while PUT validates syntax' => sub {
    my $get_returns = PVE::API2::LXC::Config->map_method_by_name('vm_config')->{returns};
    my $put_params = PVE::API2::LXC::Config->map_method_by_name('update_vm')->{parameters};

    eval {
        PVE::JSONSchema::validate(
            {
                digest => 'a' x 40,
                env => "TMPDIR=/tmp\0LD_LIBRARY_PATH=/opt/lib\0HOSTVAR",
            },
            $get_returns,
        );
    };
    is($@, '', 'GET config response schema accepts pre-existing restricted or malformed env');

    eval {
        PVE::JSONSchema::validate(
            {
                node => 'pve',
                vmid => 100,
                env => 'TMPDIR=/tmp',
            },
            $put_params,
        );
    };
    is($@, '', 'PUT config parameter schema accepts syntactically valid env');

    for my $bad ('HOSTVAR', ' LD_PRELOAD=/evil.so') {
        eval {
            PVE::JSONSchema::validate(
                {
                    node => 'pve',
                    vmid => 100,
                    env => $bad,
                },
                $put_params,
            );
        };
        like($@, qr/Parameter verification failed/, "PUT schema rejects malformed env '$bad'");
    }
};

subtest 'remote migration prepare rejects restricted and malformed env early' => sub {
    my $storage_mock = Test::MockModule->new('PVE::Storage');
    $storage_mock->mock(config => sub { return {}; });

    my $mock_env = 'LD_LIBRARY_PATH=/opt/lib';
    my $cfg_mock = Test::MockModule->new('PVE::LXC::Config');
    $cfg_mock->mock(load_config => sub { return { env => $mock_env }; });

    my $lxc_mock = Test::MockModule->new('PVE::LXC');
    $lxc_mock->mock(check_running => sub { return 0; });

    my $tunnel_opened = 0;
    my $tunnel_mock = Test::MockModule->new('PVE::Tunnel');
    $tunnel_mock->mock(
        fork_websocket_tunnel => sub {
            $tunnel_opened = 1;
            die "unexpected tunnel creation\n";
        },
    );

    eval {
        (bless { opts => { remote => { vmid => 100, conn => {} } } }, 'PVE::LXC::Migrate')
            ->prepare(100);
    };
    like(
        $@,
        qr/cannot migrate CT 100 to a remote cluster - restricted variable 'LD_LIBRARY_PATH'/,
        'remote migration prepare rejects restricted env early',
    );

    $mock_env = 'HOSTVAR';
    eval {
        (bless { opts => { remote => { vmid => 100, conn => {} } } }, 'PVE::LXC::Migrate')
            ->prepare(100);
    };
    like(
        $@,
        qr/cannot migrate CT 100 to a remote cluster - invalid environment variable entry 'HOSTVAR'/,
        'remote migration prepare rejects malformed env early',
    );
    is($tunnel_opened, 0, 'remote migration aborts before opening websocket tunnel');
};

subtest 'restore filters restricted env variables for non-root users' => sub {
    my $rpcenv = eval { PVE::RPCEnvironment->init('cli') } || PVE::RPCEnvironment->get();
    my @warnings;
    my $rest_mock = Test::MockModule->new('PVE::RESTEnvironment');
    $rest_mock->mock(warn => sub { my ($self, $msg) = @_; push @warnings, $msg; });

    my $backup = {
        env => "SAFE=1\0LD_PRELOAD=SECRET_VAL_1\0LD_PRELOAD=SECRET_VAL_DUP\0"
            . " LD_AUDIT=SECRET_VAL_2\0SECRET_MALFORMED_3\0OK=yes",
    };

    $rpcenv->set_user('user@pve');
    my $conf = {};
    PVE::LXC::Create::sanitize_and_merge_config($conf, $backup, 1, 0);
    is($conf->{env}, "SAFE=1\0OK=yes", 'restricted user keeps only safe env vars');
    is(scalar(@warnings), 1, 'restricted user receives warning for skipped env vars');
    like(
        $warnings[0],
        qr/^skipping disallowed runtime environment entries \(restricted variables: LD_PRELOAD; 2 malformed entries\), configure manually as root$/,
        'warning reports only restricted names and malformed entry count',
    );
    unlike(
        $warnings[0],
        qr/SECRET_VAL_1|SECRET_VAL_DUP|SECRET_VAL_2|SECRET_MALFORMED_3|LD_AUDIT/,
        'warning does not leak env values or malformed entries',
    );

    @warnings = ();
    my $malformed_only = { env => 'SECRET_ONLY_MALFORMED' };
    $conf = {};
    PVE::LXC::Create::sanitize_and_merge_config($conf, $malformed_only, 1, 0);
    ok(!exists($conf->{env}), 'env is omitted when all backup entries were malformed');
    is(scalar(@warnings), 1, 'warning emitted when all entries were malformed');
    like(
        $warnings[0],
        qr/^skipping disallowed runtime environment entries \(1 malformed entry\), configure manually as root$/,
        'malformed-only warning reports count without restricted variable list',
    );
    unlike(
        $warnings[0],
        qr/SECRET_ONLY_MALFORMED|restricted variables/,
        'malformed value not leaked',
    );

    @warnings = ();
    my $all_bad = { env => 'LD_PRELOAD=SECRET_VAL_ALL' };
    $conf = {};
    PVE::LXC::Create::sanitize_and_merge_config($conf, $all_bad, 1, 0);
    ok(!exists($conf->{env}), 'env is omitted if all backup entries were restricted');
    is(scalar(@warnings), 1, 'warning emitted when all env vars were skipped');
    unlike($warnings[0], qr/SECRET_VAL_ALL/, 'all-restricted warning does not leak value');

    @warnings = ();
    $conf = { env => 'CUSTOM=1' };
    PVE::LXC::Create::sanitize_and_merge_config($conf, $backup, 1, 0);
    is($conf->{env}, 'CUSTOM=1', 'explicitly provided env overrides backup without filtering');
    is(scalar(@warnings), 0, 'no warning when backup env is overridden');

    @warnings = ();
    $rpcenv->set_user('root@pam');
    $conf = {};
    PVE::LXC::Create::sanitize_and_merge_config($conf, $backup, 0, 0);
    is($conf->{env}, $backup->{env}, 'root@pam preserves all env vars from backup');
    is(scalar(@warnings), 0, 'no warning emitted for root@pam');
};

subtest 'OCI restore filters restricted env for non-root users and aborts on control characters' =>
    sub {
        my @warnings;
        my $oci_env = [];

        my $storage_mock = Test::MockModule->new('PVE::Storage');
        $storage_mock->mock(abs_filesystem_path => sub { return '/fake/oci.tar'; });

        my $ns_mock = Test::MockModule->new('PVE::LXC::Namespaces');
        $ns_mock->mock(run_in_userns => sub { return { Env => $oci_env }; });

        my $create_mock = Test::MockModule->new('PVE::LXC::Create');
        $create_mock->mock(log_warn => sub { my ($msg) = @_; push @warnings, $msg; });

        $oci_env =
        ['SAFE=1', 'LD_PRELOAD=SECRET_OCI_1', ' LD_AUDIT=SECRET_OCI_2', 'SECRET_OCI_NOEQ',
            'OK=yes'];
        @warnings = ();
        my $conf = { unprivileged => 1, lxc => [] };
        PVE::LXC::Create::restore_oci_archive({}, 'local:vztmpl/app.tar', '/fake/root', $conf, 1);
        is($conf->{env}, "SAFE=1\0OK=yes", 'restricted OCI import keeps only safe env vars');
        is(scalar(@warnings), 1, 'restricted OCI import emits one warning');
        like(
            $warnings[0],
        qr/^skipping disallowed OCI environment entries \(restricted variables: LD_PRELOAD; 2 malformed entries\), configure manually as root$/,
            'OCI warning reports only restricted names and malformed entry count',
        );
        unlike(
            $warnings[0],
            qr/SECRET_OCI_1|SECRET_OCI_2|SECRET_OCI_NOEQ|LD_AUDIT/,
            'OCI warning does not leak env values or malformed entries',
        );

        @warnings = ();
        $conf = { unprivileged => 1, lxc => [] };
        PVE::LXC::Create::restore_oci_archive({}, 'local:vztmpl/app.tar', '/fake/root', $conf, 0);
        is($conf->{env}, join("\0", @$oci_env),
            'unrestricted OCI import preserves all env entries');
        is(scalar(@warnings), 0, 'unrestricted OCI import emits no warning');

        $oci_env = ['SAFE=1', "BAD=line1\nline2"];
        for my $restricted (1, 0) {
            $conf = { unprivileged => 1, lxc => [] };
            eval {
                PVE::LXC::Create::restore_oci_archive(
                    {}, 'local:vztmpl/app.tar', '/fake/root', $conf, $restricted,
                );
            };
            like(
                $@,
                qr/forbidden control characters/,
                "OCI import with control characters aborts (restricted=$restricted)",
            );
        }
    };

done_testing();
