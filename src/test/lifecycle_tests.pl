#!/usr/bin/perl

# Runs API calls that create, restore, update and migrate containers against a fake cluster
# filesystem in a working directory, with storage and container runtime operations mocked.

use v5.36;

use lib qw(..);

# Modules of pve-ha-manager and pve-manager are not build dependencies, so stub the ones that the
# tested modules load. Tests that call into them mock the functions they need.
BEGIN {
    $INC{'PVE/HA/Config.pm'} = $INC{'PVE/HA/Env/PVE2.pm'} = __FILE__;
}

use File::Path qw(make_path remove_tree);
use JSON;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test::MockModule;
use Test::More;

use PVE::Cluster;
use PVE::GuestHelpers;
use PVE::INotify;
use PVE::Tools qw(file_get_contents file_set_contents);

use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::LXC::Migrate;

use PVE::API2::LXC;

my $WORKDIR = 'lifecycle-working';
my $NODENAME = PVE::INotify::nodename();
my $BACKUP_VOLID = 'local:backup/vzdump-lxc-100-2026_01_01-00_00_00.tar.zst';
my $PBS_VOLID = 'pbs:backup/ct/100/2026-01-01T00:00:00Z';

remove_tree($WORKDIR);
make_path("$WORKDIR/lock");

# locks are taken and firewall configs are kept in the working directory
$PVE::GuestHelpers::lockdir = "$WORKDIR/lock";
$PVE::GuestHelpers::firewall_config_dir = "$WORKDIR/firewall";

my sub firewall_config($vmid) {
    return PVE::GuestHelpers::get_firewall_config_raw($vmid);
}

my sub set_firewall_config($vmid, $raw) {
    PVE::GuestHelpers::set_firewall_config_raw($vmid, $raw);
}

# Fake cluster filesystem

my sub cfs_file($path) {
    return "$WORKDIR/cfs/$path";
}

my sub ct_config_path($vmid, $node = undef) {
    return "nodes/" . ($node // $NODENAME) . "/lxc/$vmid.conf";
}

my sub write_raw_config($vmid, $raw, $node = undef) {
    my $file = cfs_file(ct_config_path($vmid, $node));
    make_path($file =~ s|/[^/]+$||r);
    file_set_contents($file, $raw);
}

my sub read_raw_config($vmid, $node = undef) {
    my $file = cfs_file(ct_config_path($vmid, $node));
    return -f $file ? file_get_contents($file) : undef;
}

my $written = {}; # VMID => the written raw configs, in the order of the writes

my $storage_cfg = {
    ids => {
        local => {
            type => 'dir',
            path => '/var/lib/vz',
            content => { rootdir => 1, images => 1, backup => 1, vztmpl => 1 },
        },
        iso => {
            type => 'dir',
            path => '/mnt/iso',
            content => { iso => 1 },
        },
        pbs => {
            type => 'pbs',
            content => { backup => 1 },
        },
    },
};

# recording used guest IDs needs the cluster filesystem and is not what gets tested here
my $guest_id_module = Test::MockModule->new('PVE::GuestID');
$guest_id_module->mock(register_used_id => sub { return; });

my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    cfs_update => sub { },
    check_cfs_quorum => sub { },
    check_node_exists => sub { },
    get_config => sub {
        my ($path) = @_;
        my $file = cfs_file($path);
        return -f $file ? file_get_contents($file) : undef;
    },
    cfs_read_file => sub {
        my ($path) = @_;
        die "unexpected read of '$path'\n" if $path !~ m|^nodes/[^/]+/lxc/\d+\.conf$|;
        my $file = cfs_file($path);
        return undef if !-f $file;
        return PVE::LXC::Config::parse_pct_config("/etc/pve/$path", file_get_contents($file));
    },
    cfs_write_file => sub {
        my ($path, $conf) = @_;
        die "unexpected write of '$path'\n" if $path !~ m|^nodes/[^/]+/lxc/\d+\.conf$|;
        my $raw = PVE::LXC::Config::write_pct_config("/etc/pve/$path", $conf);
        my $file = cfs_file($path);
        make_path($file =~ s|/[^/]+$||r);
        file_set_contents($file, $raw);
        push $written->{ ($path =~ m|/(\d+)\.conf$|)[0] }->@*, $raw;
    },
    check_vmid_unused => sub {
        my ($vmid, $noerr) = @_;
        return 1 if !-f cfs_file(ct_config_path($vmid));
        return undef if $noerr;
        die "CT $vmid already exists on node '$NODENAME'\n";
    },
);

# runs once between the checks of the create API call and its reservation, if set
my $in_between;

my $api_module = Test::MockModule->new('PVE::API2::LXC');
$api_module->mock(
    cfs_read_file => sub {
        my ($path) = @_;
        die "unexpected read of '$path'\n" if $path ne 'storage.cfg';
        return $storage_cfg;
    },
);

my $config_module = Test::MockModule->new('PVE::LXC::Config');
$config_module->mock(
    config_file => sub {
        my ($class, $vmid, $node) = @_;
        return cfs_file(ct_config_path($vmid, $node));
    },
    config_file_lock => sub {
        my ($class, $vmid) = @_;
        return "$WORKDIR/lock/pve-config-$vmid.lock";
    },
);

# Fake environment, records task output

my $task_log = '';

package PVE::LXC::Test::RPCEnvironment {

    sub new($class, $user) {
        return bless { user => $user, type => 'cli' }, $class;
    }

    sub get_user { return $_[0]->{user} }

    # 'deny' maps paths to 1 or to the privileges that the checks of the path do not grant
    sub check($self, $user, $path, $privs, $noerr = undef) {
        my $deny = $self->{deny}->{$path};
        return 1 if !$deny || (ref($deny) && !grep { $deny->{$_} } @$privs);
        return 0 if $noerr;
        die "permission check failed ($path, " . join(', ', @$privs) . ")\n";
    }
    sub check_vm_perm { return 1 }
    sub check_pool_exist { return 1 }

    sub warn($self, $msg) {
        $task_log .= "WARN: $msg\n";
    }

    sub fork_worker($self, $type, $id, $user, $function, @) {
        my $upid = "UPID:$NODENAME:$type:$id";
        $function->($upid);
        return $upid;
    }
}

my $rpcenv = PVE::LXC::Test::RPCEnvironment->new('root@pam');

my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(get => sub { return $rpcenv });

my $restenv_module = Test::MockModule->new('PVE::RESTEnvironment');
$restenv_module->mock(
    log_warn => sub {
        my ($msg) = @_;
        chomp($msg);
        $task_log .= "WARN: $msg\n";
    },
);

# Runs $code as $user, who lacks what $deny lists, see the check method above.
my sub as_user($user, $deny, $code) {
    $rpcenv = PVE::LXC::Test::RPCEnvironment->new($user);
    $rpcenv->{deny} = $deny;
    my $res = $code->();
    $rpcenv = PVE::LXC::Test::RPCEnvironment->new('root@pam');

    return $res;
}

# Runs $code like a task, with its output going to the task log. Returns the error, if any.
my sub run_task($code) {
    $task_log = '';
    my $output = '';
    eval {
        # both append, as the warnings get appended as well
        local (*STDOUT, *STDERR);
        open(STDOUT, '>>', \$output) or die "unable to capture output - $!\n";
        open(STDERR, '>>', \$output) or die "unable to capture errors - $!\n";
        local $SIG{__WARN__} = sub { $output .= "WARN: $_[0]" };
        $code->();
    };
    my $err = $@;
    $task_log = $output . $task_log;

    return $err;
}

# Runs $code with the functions in the hash $mocks in place of the ones of the mocked module
# $module, and puts back what they were before, be it a mock or the real function.
my sub with_mock($module, $mocks, $code) {
    my $package = $module->get_package();
    my %before = map { $_ => $module->is_mocked($_) && $package->can($_) } keys %$mocks;
    $module->mock(%$mocks);
    my $res = eval { $code->() };
    my $err = $@;
    for my $name (keys %before) {
        if ($before{$name}) {
            $module->mock($name => $before{$name});
        } else {
            $module->unmock($name);
        }
    }
    die $err if $err;

    return $res;
}

# Fake storage and container runtime

my $backup_raw_config; # the config in the backup, undef for none
my $backup_read_error; # set to let reading the config of the backup fail
my $backup_fw_config; # the firewall config in the backup, if any
my $hook_error; # set to let the setup hooks at the end of a create or restore fail

my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(
    config => sub { return $storage_cfg },
    activate_storage => sub {
        if (my $code = $in_between) {
            undef $in_between;
            $code->();
        }
    },
    activate_volumes => sub { },
    deactivate_volumes => sub { },
    check_volume_access => sub { },
    storage_check_enabled => sub {
        my ($cfg, $storeid) = @_;
        return $storage_cfg->{ids}->{$storeid};
    },
    storage_config => sub {
        my ($cfg, $storeid) = @_;
        return $storage_cfg->{ids}->{$storeid} // die "storage '$storeid' does not exist\n";
    },
    storage_has_feature => sub { return 0 },
    get_bandwidth_limit => sub { return undef },
    parse_volname => sub {
        my ($cfg, $volid) = @_;
        die "unexpected volume '$volid'\n" if $volid ne $PBS_VOLID;
        return ('backup', 'ct/100/2026-01-01T00:00:00Z', 100, undef, undef, undef, 'pbs-ct');
    },
);

my $lxc_module = Test::MockModule->new('PVE::LXC');
$lxc_module->mock(
    check_running => sub { return 0 },
    create_disks => sub {
        my ($storecfg, $vmid, $settings, $conf, $pending, $allocated) = @_;
        my $vollist = $allocated // [];
        for my $ms (sort keys %$settings) {
            my $volid = "local:$vmid/vm-$vmid-disk-$ms.raw";
            $conf->{$ms} = "$volid,size=4G";
            push @$vollist, $volid;
        }
        return $vollist;
    },
    destroy_disks => sub { return [] },
    destroy_lxc_container => sub {
        my ($storecfg, $vmid, $conf, $replacement_conf) = @_;
        if (defined($replacement_conf)) {
            PVE::LXC::Config->write_config($vmid, $replacement_conf);
        } else {
            PVE::LXC::Config->destroy_config($vmid);
        }
        return [];
    },
    mount_all => sub {
        my ($vmid) = @_;
        my $rootdir = "$WORKDIR/rootfs/$vmid";
        make_path($rootdir);
        return $rootdir;
    },
    umount_all => sub { },
    create_ifaces_ipams_ips => sub { },
    delete_ifaces_ipams_ips => sub { },
    update_lxc_config => sub { },
    # not the socket of a migration that runs on the host
    mtunnel_socket => sub {
        my ($vmid) = @_;
        return "$WORKDIR/ct-$vmid.mtunnel";
    },
);

my $create_module = Test::MockModule->new('PVE::LXC::Create');
$create_module->mock(
    archive_is_oci_format => sub { return 0 },
    recover_config => sub {
        my ($storecfg, $volid, $vmid) = @_;
        die $backup_read_error if defined($backup_read_error);
        my $conf = PVE::LXC::Config::parse_pct_config("/lxc/$vmid.conf", $backup_raw_config);
        delete $conf->{snapshots};
        my $mp_param = {};
        PVE::LXC::Config->foreach_volume($conf,
            sub { $mp_param->{ $_[0] } = $conf->{ $_[0] } });
        return wantarray ? ($conf, $mp_param) : $conf;
    },
    restore_archive => sub {
        my ($storecfg, $archive, $rootdir, $conf) = @_;
        make_path("$rootdir/etc/vzdump");
        file_set_contents("$rootdir/etc/vzdump/pct.conf", $backup_raw_config)
            if defined($backup_raw_config);
        file_set_contents("$rootdir/etc/vzdump/pct.fw", $backup_fw_config)
            if defined($backup_fw_config);
    },
);

# the same backup on a Proxmox Backup Server, which has the configs as files of their own
my $pbs_module = Test::MockModule->new('PVE::Storage::PBSPlugin');
$pbs_module->mock(
    run_client_cmd => sub {
        my ($scfg, $storeid, $cmd) = @_;
        die "unexpected client command '$cmd'\n" if $cmd ne 'files';
        my @files = ('pct.conf', defined($backup_fw_config) ? 'fw.conf' : ());
        return [map { { filename => "$_.blob" } } @files];
    },
    run_raw_client_cmd => sub {
        my ($scfg, $storeid, $cmd, $param, %opts) = @_;
        my ($name, $file, $target) = @$param;
        die "unexpected client command '$cmd $file $target'\n"
            if $cmd ne 'restore' || $target ne '-';
        my $files = { 'pct.conf' => $backup_raw_config, 'fw.conf' => $backup_fw_config };
        my $raw = $files->{$file} // die "backup has no file '$file'\n";
        if (my ($fd) = ($opts{output} // '') =~ m/^>&(\d+)$/) {
            open(my $out, '>&', $fd) or die "unable to write to file descriptor $fd - $!\n";
            print $out $raw;
            close($out) or die "unable to write to file descriptor $fd - $!\n";
        } else {
            $opts{outfunc}->($_) for split(/\n/, $raw);
        }
    },
);

my $setup_module = Test::MockModule->new('PVE::LXC::Setup');
$setup_module->mock(new => sub { return bless {}, 'PVE::LXC::Test::Setup' });

package PVE::LXC::Test::Setup {
    sub post_create_hook { die $hook_error if defined($hook_error) }
    sub post_restore_hook { die $hook_error if defined($hook_error) }
}

my $firewall_module = Test::MockModule->new('PVE::Firewall');
$firewall_module->mock(
    remove_vmfw_conf => sub {
        my ($vmid) = @_;
        PVE::GuestHelpers::set_firewall_config_raw($vmid, undef);
    },
);

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(assemble_tunnel_ticket => sub { return 'ticket' });

my sub backup_config($meta = undef) {
    my $raw = <<~'EOF';
        arch: amd64
        hostname: backup
        memory: 2048
        ostype: debian
        rootfs: local:100/vm-100-disk-0.raw,size=8G
        unprivileged: 1
        EOF
    $raw .= "meta: $meta\n" if defined($meta);

    return $raw;
}

my sub existing_config($meta = undef) {
    my $raw = <<~'EOF';
        arch: amd64
        hostname: existing
        memory: 512
        ostype: debian
        rootfs: local:200/vm-200-disk-0.raw,size=4G
        unprivileged: 1
        EOF
    $raw .= "meta: $meta\n" if defined($meta);

    return $raw;
}

my sub reset_configs {
    remove_tree("$WORKDIR/cfs", "$WORKDIR/rootfs", "$WORKDIR/firewall");
    $written = {};
}

# Removes all configs and puts the fakes back to their defaults, with a backup that has the config
# backup_config().
my sub reset_state {
    reset_configs();
    $rpcenv = PVE::LXC::Test::RPCEnvironment->new('root@pam');
    $backup_raw_config = backup_config();
    ($backup_read_error, $hook_error, $in_between) = ();
    $backup_fw_config = undef;
}

# API call helpers

my sub create_ct($vmid, $param = undef) {
    return run_task(sub {
        PVE::API2::LXC->create_vm({
            node => $NODENAME,
            vmid => $vmid,
            ostemplate => 'local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst',
            hostname => "ct$vmid",
            ($param // {})->%*,
        });
    });
}

my sub restore_ct($vmid, $param = undef) {
    return run_task(sub {
        PVE::API2::LXC->create_vm({
            node => $NODENAME,
            vmid => $vmid,
            ostemplate => $BACKUP_VOLID,
            restore => 1,
            ($param // {})->%*,
        });
    });
}

# Runs the migration tunnel for $vmid with the commands @commands, which are sent at once, and
# returns the error of the task, if any, and the replies.
my sub run_mtunnel($vmid, @commands) {
    socketpair(my $tunnel_end, my $client_end, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair failed - $!\n";
    for my $command (@commands) {
        print $client_end JSON::encode_json($command) . "\n";
    }
    $client_end->flush();
    shutdown($client_end, 1);

    my $socket_module = Test::MockModule->new('IO::Socket::UNIX');
    $socket_module->mock(
        new => sub { return bless { conn => $tunnel_end }, 'PVE::LXC::Test::Socket' });

    my $err = run_task(sub { PVE::API2::LXC->mtunnel({ node => $NODENAME, vmid => $vmid }) });

    close($tunnel_end);
    my $replies = [map { JSON::decode_json($_) } <$client_end>];
    close($client_end);

    return ($err, $replies);
}

package PVE::LXC::Test::Socket {
    sub accept { return $_[0]->{conn} }
}

my $INCOMING_CONFIG = <<~'EOF';
    arch: amd64
    hostname: incoming
    memory: 1024
    ostype: debian
    rootfs: local:300/vm-300-disk-0.raw,size=4G
    unprivileged: 1
    EOF

# Runs a remote migration of CT $vmid on the source, with the functions of the tunnel replaced by
# the ones in the hash $tunnel. Returns the error, if any, and the log of the migration.
my sub migrate_remote($vmid, $opts, $tunnel) {
    my $log = '';
    my $migrate_module = Test::MockModule->new('PVE::AbstractMigrate');
    $migrate_module->mock(log => sub { $log .= "$_[1]: $_[2]\n" });
    my $tunnel_module = Test::MockModule->new('PVE::Tunnel');
    $tunnel_module->mock($tunnel->%*);

    my $err = run_task(sub {
        my $remote = { vmid => 300, conn => { host => '192.0.2.1', port => 8006 } };
        PVE::LXC::Migrate->migrate(
            'remote-node',
            '192.0.2.1',
            $vmid,
            { remote => $remote, $opts->%* },
        );
    });

    return ($err, $log);
}

# Tests

subtest 'create and restore write the config of the container' => sub {
    reset_state();

    is(create_ct(201), '', 'create succeeds') or diag($task_log);
    my $conf = PVE::LXC::Config->load_config(201);
    is($conf->{hostname}, 'ct201', 'create: given option is applied');
    ok(!defined($conf->{lock}), 'create: lock is removed');

    is(restore_ct(202), '', 'restore to an unused VMID succeeds') or diag($task_log);
    is(PVE::LXC::Config->load_config(202)->{hostname}, 'backup',
        'config of the backup is used');

    write_raw_config(200, existing_config());
    my $err = restore_ct(200, { force => 1, hostname => 'given' });
    is($err, '', 'restore over a container succeeds') or diag($task_log);
    $conf = PVE::LXC::Config->load_config(200);
    is($conf->{hostname}, 'given', 'given option wins over the one of the backup');
    is($conf->{memory}, 2048, 'other options come from the backup');
    ok(!defined($conf->{lock}), 'restore: lock is removed');
};

subtest 'restore over a container keeps it if replacing it fails early' => sub {
    my $kept = sub($name, $extra_config, $mocks, $expected_err) {
        reset_state();
        write_raw_config(200, existing_config() . $extra_config);
        set_firewall_config(200, "rules of the container\n");

        my $err = with_mock($lxc_module, $mocks, sub { restore_ct(200, { force => 1 }) });
        like($err, $expected_err, "$name: restore fails");
        is(firewall_config(200), "rules of the container\n", "$name: firewall config is kept");
        ok(defined(read_raw_config(200)), "$name: config is kept") or return;
        my $conf = PVE::LXC::Config->load_config(200);
        is($conf->{hostname}, 'existing', "$name: config is the one of the container");
        is($conf->{rootfs}, 'local:200/vm-200-disk-0.raw,size=4G', "$name: volume is kept");
        ok(!defined($conf->{lock}), "$name: lock is removed");
    };

    $kept->(
        'allocation fails',
        '',
        { create_disks => sub { die "unable to allocate volume - storage full\n" } },
        qr/storage full/,
    );
    # the real function checks this before it removes anything
    my $in_use =
        "base volume 'local:200/base-200-disk-0.raw' is still in use by linked clone\n";
    $kept->(
        'template with linked clones',
        "template: 1\n",
        { destroy_lxc_container => sub { die $in_use } },
        qr/still in use by linked clone/,
    );
};

subtest 'create and restore do not change a container that the checks were not done for' => sub {
    my $other_raw = existing_config() =~ s/^hostname: existing$/hostname: other/mr;
    # the guest list of the reservation is the one of the start of the API call
    my $stale_guest_list = { check_vmid_unused => sub { return 1 } };

    my $refused = sub($name, $call) {
        reset_state();
        $in_between = sub { write_raw_config(200, $other_raw) };
        my $err = with_mock($cluster_module, $stale_guest_list, $call);
        like($err, qr/CT 200 already exists/, "created in between: $name is refused");
        is(read_raw_config(200), $other_raw, "created in between: $name changes nothing");
    };
    $refused->('create', sub { create_ct(200) });
    $refused->('restore', sub { restore_ct(200) });
    # a user who may create CT 200 in the pool, but not overwrite it
    $refused->(
        'restore with force',
        sub {
            my $param = { force => 1, pool => 'pool1' };
            return as_user('user@pve', { '/vms/200' => 1 }, sub { restore_ct(200, $param) });
        },
    );

    reset_state();
    write_raw_config(200, existing_config());
    $in_between = sub { write_raw_config(200, existing_config() . "protection: 1\n") };
    my $err = restore_ct(200, { force => 1 });
    like(
        $err,
        qr/^unable to restore CT 200 - protection mode enabled$/,
        'protection set in between: restore is refused',
    );
    my $conf = PVE::LXC::Config->load_config(200);
    is($conf->{hostname}, 'existing', 'protection set in between: container is kept');
    ok(!defined($conf->{lock}), 'protection set in between: lock is removed');
};

subtest 'remote migration cleans up the target if it fails before the transfer' => sub {
    reset_state();
    write_raw_config(200, existing_config());
    my $raw = read_raw_config(200);

    my ($commands, $cleanup);
    my $tunnel = sub($version) {
        ($commands, $cleanup) = (0);
        return {
            fork_websocket_tunnel => sub { return { version => $version, age => 0 } },
            write_tunnel => sub { $commands++; return {}; },
            finish_tunnel => sub { (undef, $cleanup) = @_ },
        };
    };
    my $version = $PVE::LXC::Migrate::WS_TUNNEL_VERSION;

    my ($err, $log) = migrate_remote(200, {}, $tunnel->($version - 1));
    like($err, qr/migration aborted/, 'migration to an older target fails');
    like($log, qr/^err: .*Remote tunnel endpoint too old/m, 'target is reported as too old');
    is($cleanup, 1, 'older target is asked to clean up');
    is($commands, 0, 'nothing else is sent to the target');

    ($err, $log) = migrate_remote(200, {}, $tunnel->($version + 1));
    like($err, qr/migration aborted/, 'migration to an incompatible target fails');
    like($log, qr/^err: .*Remote tunnel endpoint not compatible/m, 'target is reported');
    is($cleanup, 1, 'incompatible target is asked to clean up');
    is(read_raw_config(200), $raw, 'config of the source is unchanged');

    my $does_not_stop = {
        check_running => sub { return 1 },
        vm_stop => sub { die "container did not stop\n" },
    };
    ($err, $log) = with_mock(
        $lxc_module,
        $does_not_stop,
        sub { [migrate_remote(200, { restart => 1 }, $tunnel->($version))] },
    )->@*;
    like(
        $err,
        qr/migration aborted/,
        'restart migration of a container that does not stop fails',
    );
    like($log, qr/^err: .*container did not stop/m, 'failed shutdown is reported');
    is($cleanup, 1, 'target is asked to clean up');
    ok(!defined(PVE::LXC::Config->load_config(200)->{lock}), 'source is not left locked');
};

subtest 'migration tunnel logs failed commands and cleans up after an early end' => sub {
    my $config_cmd = { cmd => 'config', conf => $INCOMING_CONFIG };

    reset_state();
    my ($err, $replies) = run_mtunnel(300, $config_cmd, { cmd => 'quit', cleanup => 0 });
    is($err, '', 'tunnel exits normally after quit') or diag(explain($replies), $task_log);
    ok($replies->[0]->{success}, 'config command succeeds');
    my $conf = PVE::LXC::Config->load_config(300);
    is($conf->{hostname}, 'incoming', 'config of the source is written');
    is($conf->{lock}, 'migrate', 'config is locked for the migration');

    reset_state();
    ($err, $replies) = run_mtunnel(300);
    like($err, qr/mtunnel exited unexpectedly/, 'tunnel that ends without a command fails');
    like(
        $task_log,
        qr/^WARN: tunnel closed before the config arrived, cleaning up$/m,
        'cleanup is logged',
    );
    ok(!defined(read_raw_config(300)), 'reserved config is removed');

    reset_state();
    my $broken = $INCOMING_CONFIG =~ s/^rootfs: local:/rootfs: iso:/mr;
    ($err, $replies) = run_mtunnel(300, { cmd => 'config', conf => $broken });
    like($err, qr/mtunnel exited unexpectedly/, 'tunnel that ends after a failed config fails');
    ok(!$replies->[0]->{success}, 'config command fails');
    like(
        $task_log,
        qr/^WARN: failed to handle 'config' command - /m,
        'failed command is logged',
    );
    ok(!defined(read_raw_config(300)), 'reserved config is removed after a failed config');

    reset_state();
    ($err, $replies) = run_mtunnel(300, $config_cmd);
    like($err, qr/mtunnel exited unexpectedly/, 'tunnel that ends after the config fails');
    unlike($task_log, qr/cleaning up/, 'no cleanup once the config arrived');
    is(PVE::LXC::Config->load_config(300)->{lock}, 'migrate', 'config that arrived is kept');
};

subtest 'restore replaces the firewall config with the one of the backup' => sub {
    for my $archive ($BACKUP_VOLID, $PBS_VOLID) {
        my $name = $archive eq $PBS_VOLID ? 'backup server' : 'archive file';
        my $param = { ostemplate => $archive };

        reset_state();
        set_firewall_config(200, "older rules\n");
        is(restore_ct(200, $param), '', "$name without firewall config: restore succeeds")
            or diag($task_log);
        is(firewall_config(200), "older rules\n", "$name: existing firewall config is kept");

        # must arrive byte for byte
        my $backup_rules = "backup rules\r\nwithout a final newline";
        $backup_fw_config = $backup_rules;
        is(restore_ct(201, $param), '', "$name with firewall config: restore succeeds")
            or diag($task_log);
        is(firewall_config(201), $backup_rules, "$name: its firewall config is written");
        is(restore_ct(200, { force => 1, $param->%* }), '', "$name: restore over a container")
            or diag($task_log);
        is(firewall_config(200), $backup_rules, "$name: its firewall config replaces one");

        # 'VM.Backup' allows overwriting the container, but not changing its firewall config
        set_firewall_config(200, "rules of the container\n");
        my $deny = { '/vms/200' => { 'VM.Allocate' => 1 } };
        my $err =
            as_user('user@pve', $deny, sub { restore_ct(200, { force => 1, $param->%* }) });
        is($err, '', "$name: restore with only VM.Backup succeeds") or diag($task_log);
        is(
            firewall_config(200),
            "rules of the container\n",
            "$name: firewall config of the container is kept",
        );
        like(
            $task_log,
            qr/^WARN: ignoring firewall config from backup archive, lacking API permission/m,
            "$name: ignored firewall config is logged",
        );
        like(
            $task_log,
            qr/^WARN: old firewall configuration of CT 200 left in place!$/m,
            "$name: kept firewall config is logged",
        );
    }
};

subtest 'firewall config follows its container if a create or restore fails' => sub {
    # the firewall configs written, each with whether the VMID was reserved at that time
    my @writes;
    my $set_raw = PVE::GuestHelpers->can('set_firewall_config_raw');
    my $helpers_module = Test::MockModule->new('PVE::GuestHelpers');
    $helpers_module->mock(
        set_firewall_config_raw => sub {
            my ($vmid, $raw) = @_;
            push @writes, [$raw, defined(read_raw_config($vmid)) ? 'reserved' : 'free'];
            return $set_raw->(@_);
        },
    );

    my $failed = sub($name, $before, $setup, $call, $after = $before) {
        reset_state();
        $hook_error = "setup hook failed\n";
        set_firewall_config(200, $before) if defined($before);
        $setup->();
        @writes = ();
        my $err = $call->();
        isnt($err, '', "$name: fails");
        is(firewall_config(200), $after, "$name: firewall config afterwards");
        ok(!defined(read_raw_config(200)), "$name: VMID is released");
        return $err;
    };
    my $with_fw = sub { $backup_fw_config = "backup rules\n" };

    $failed->('create', "older rules\n", sub { }, sub { create_ct(200) });
    $failed->(
        'restore without firewall config',
        "older rules\n",
        sub { },
        sub { restore_ct(200) },
    );
    for my $archive ($BACKUP_VOLID, $PBS_VOLID) {
        my $name =
            'restore from ' . ($archive eq $PBS_VOLID ? 'backup server' : 'archive file');
        my $restore = sub { restore_ct(200, { ostemplate => $archive }) };

        $failed->("$name, no firewall config before", undef, $with_fw, $restore);
        $failed->("$name, firewall config before", "older rules\n", $with_fw, $restore);
        is_deeply(
            \@writes,
            [["backup rules\n", 'reserved'], ["older rules\n", 'reserved']],
            "$name: firewall config is put back before the VMID is released",
        );
    }

    my $mocked_client_cmd = PVE::Storage::PBSPlugin->can('run_raw_client_cmd');
    my $no_fw_conf = {
        run_raw_client_cmd => sub {
            my ($scfg, $storeid, $cmd, $param) = @_;
            die "unable to read fw.conf\n" if $param->[1] eq 'fw.conf';
            return $mocked_client_cmd->(@_);
        },
    };
    my $err = $failed->(
        'restore from backup server that fails to read the firewall config',
        "older rules\n",
        sub { $with_fw->(); $hook_error = undef; },
        sub {
            my $restore = sub { restore_ct(200, { ostemplate => $PBS_VOLID }) };
            return with_mock($pbs_module, $no_fw_conf, $restore);
        },
    );
    like($err, qr/unable to read fw\.conf/, 'the read error is the reason');

    # the firewall config of a container that the restore destroyed goes with it
    for my $user ('root@pam', 'user@pve') {
        my $deny = $user eq 'root@pam' ? {} : { '/vms/200' => { 'VM.Allocate' => 1 } };
        $failed->(
            "restore over a container by $user",
            "rules of the container\n",
            sub { $with_fw->(); write_raw_config(200, existing_config()); },
            sub {
                as_user($user, $deny, sub { restore_ct(200, { force => 1 }) });
            },
            undef,
        );
    }
};

subtest 'failed create or restore keeps the VMID if the cleanup leaves something behind' => sub {
    my $kept = sub($name, $err, $left) {
        like($err, qr/setup hook failed|storage full/, "$name: fails");
        my $msg = "keeping CT 200 locked, the cleanup left behind $left";
        like($task_log, qr/^WARN: \Q$msg\E$/m, "$name: what is left is logged");
        ok(defined(read_raw_config(200)), "$name: config is kept") or return;
        is(PVE::LXC::Config->load_config(200)->{lock}, 'create', "$name: and stays locked");
    };
    my $setup = sub {
        reset_state();
        $hook_error = "setup hook failed\n";
    };
    my $keep_all = { destroy_disks => sub { return $_[1] } };

    $setup->();
    my $err = with_mock($lxc_module, $keep_all, sub { restore_ct(200) });
    $kept->('volume that cannot be freed', $err, "volume 'local:200/vm-200-disk-rootfs.raw'");

    # create_disks leaves the volumes it allocated before a failure to the caller
    $setup->();
    my $partly = {
        $keep_all->%*,
        create_disks => sub {
            my ($storecfg, $vmid, $settings, $conf, $pending, $allocated) = @_;
            push $allocated->@*, 'local:200/vm-200-disk-0.raw', 'local:200/vm-200-disk-1.raw';
            die "unable to allocate volume - storage full\n";
        },
    };
    $err = with_mock($lxc_module, $partly, sub { create_ct(200) });
    $kept->(
        'volumes of a failed allocation',
        $err,
        "volume 'local:200/vm-200-disk-0.raw', volume 'local:200/vm-200-disk-1.raw'",
    );

    $setup->();
    write_raw_config(200, existing_config());
    set_firewall_config(200, "rules of the container\n");
    $backup_fw_config = "backup rules\n";
    my $mocked_destroy = PVE::LXC->can('destroy_lxc_container');
    my $old_left = {
        destroy_lxc_container => sub {
            $mocked_destroy->(@_);
            return ['local:200/vm-200-disk-0.raw'];
        },
    };
    $err = with_mock($lxc_module, $old_left, sub { restore_ct(200, { force => 1 }) });
    $kept->('volume of the old container', $err, "volume 'local:200/vm-200-disk-0.raw'");
    is(firewall_config(200), "rules of the container\n", 'its firewall config is put back');

    $setup->();
    $backup_fw_config = "backup rules\n";
    my $set_raw = PVE::GuestHelpers->can('set_firewall_config_raw');
    my $helpers_module = Test::MockModule->new('PVE::GuestHelpers');
    $helpers_module->mock(
        set_firewall_config_raw => sub {
            my ($vmid, $raw) = @_;
            die "unable to remove the firewall config - Input/output error\n" if !defined($raw);
            return $set_raw->(@_);
        },
    );
    $err = restore_ct(200);
    $kept->('firewall config that cannot be put back', $err, 'the firewall config');
    like(
        $task_log,
        qr/^WARN: unable to reset the firewall config - .* Input\/output error$/m,
        'the reason is logged',
    );
};

subtest 'volumes that cannot be freed are returned or left to the caller' => sub {
    reset_state();
    my (@allocated, @freed, $busy, $formats);
    my $storage_mocks = {
        vdisk_alloc => sub {
            my ($cfg, $storeid, $vmid) = @_;
            push @allocated, "$storeid:$vmid/vm-$vmid-disk-" . scalar(@allocated) . ".raw";
            return $allocated[-1];
        },
        vdisk_free => sub {
            my ($cfg, $volid) = @_;
            die "unable to free '$volid' - storage busy\n" if $busy->{$volid};
            push @freed, $volid;
        },
    };
    my $lxc_mocks = {
        destroy_disks => $lxc_module->original('destroy_disks'),
        # formatting the second volume fails
        format_disk => sub { die "formatting failed\n" if ++$formats == 2 },
    };
    my $create_disks = sub(@allocated_by_caller) {
        (@allocated, @freed, $formats) = ();
        my $settings = { rootfs => 'local:4', mp0 => 'local:4,mp=/mnt' };
        my $run = sub {
            $lxc_module->original('create_disks')
                ->($storage_cfg, 200, $settings, {}, 0, @allocated_by_caller);
        };
        my $err = run_task(sub {
            with_mock(
                $storage_module,
                $storage_mocks,
                sub { with_mock($lxc_module, $lxc_mocks, $run) },
            );
        });
        like($err, qr/formatting failed/, 'allocating the volumes fails');
    };

    $create_disks->();
    is(scalar(@allocated), 2, 'two volumes got allocated');
    is_deeply([sort @freed], \@allocated, 'create_disks frees them');

    my $vollist = [];
    $create_disks->($vollist);
    is_deeply($vollist, \@allocated, 'with an array of the caller, they are added to it');
    is_deeply(\@freed, [], 'and freeing them is left to the caller');

    $busy = { $allocated[1] => 1 };
    my $left = with_mock(
        $storage_module,
        $storage_mocks,
        sub {
            run_task(sub {
                $vollist = $lxc_module->original('destroy_disks')->($storage_cfg, $vollist);
            });
        },
    );
    is_deeply($vollist, [$allocated[1]], 'destroy_disks returns the volume it could not free');
    is_deeply(\@freed, [$allocated[0]], 'and frees the other one');
};

subtest 'create or restore that does not get the config lock releases an unused VMID' => sub {
    # inherited, so the mock calls the method of the base class
    my $lock_config = PVE::LXC::Config->can('lock_config');
    my $calls;
    my $timeout = {
        lock_config => sub {
            die "can't lock file '/run/lock/lxc/pve-config-200.lock' - got timeout\n"
                if !$calls++;
            die "lock_config mock called too often\n" if $calls > 20;
            return $lock_config->(@_);
        },
    };

    for my $call (sub { create_ct(200) }, sub { restore_ct(200) }) {
        reset_state();
        $calls = 0;
        like(with_mock($config_module, $timeout, $call), qr/got timeout/, 'unused VMID: fails');
        ok(!defined(read_raw_config(200)), 'unused VMID: the reservation is removed');
    }

    reset_state();
    write_raw_config(200, existing_config());
    $calls = 0;
    my $err = with_mock($config_module, $timeout, sub { restore_ct(200, { force => 1 }) });
    like($err, qr/got timeout/, 'existing container: restore fails');
    my $conf = PVE::LXC::Config->load_config(200);
    is($conf->{hostname}, 'existing', 'existing container: config is kept');
    ok(!defined($conf->{lock}), 'existing container: its lock is removed');
};

subtest 'restore does not create a container if the user may only overwrite it' => sub {
    # 'VM.Backup' allows overwriting the container, but not creating one
    my $deny = { '/vms/200' => { 'VM.Allocate' => 1 } };
    my $restore = sub { restore_ct(200, { force => 1 }) };

    reset_state();
    write_raw_config(200, existing_config());
    $in_between = sub { PVE::LXC::Config->destroy_config(200) };
    my $err = as_user('user@pve', $deny, $restore);
    my $missing = qr/Configuration file 'nodes\/[^\/]+\/lxc\/200\.conf' does not exist/;
    like(
        $err,
        qr/^unable to restore CT 200 - $missing$/,
        'removed in between: restore is refused',
    );
    ok(!$written->{200}, 'removed in between: no config is written for the VMID');

    reset_state();
    write_raw_config(200, existing_config());
    is(as_user('user@pve', $deny, $restore), '', 'restore over the container succeeds')
        or diag($task_log);

    reset_state();
    write_raw_config(200, existing_config());
    $in_between = sub { PVE::LXC::Config->destroy_config(200) };
    is($restore->(), '', 'removed in between: a user who may create it gets a new container')
        or diag($task_log);
};

subtest 'network options are only applied once the worker replaces the container' => sub {
    # an option with the MAC address that the existing container has
    my $mac = 'BC:24:11:00:00:01';
    my $net = "name=eth0,bridge=vnet0,hwaddr=$mac,ip=dhcp";
    my $existing_raw = existing_config() . "net0: $net,type=veth\n";

    my (@sdn_calls, $ipam); # $ipam: bridge => MAC => hostname
    my $vnets_module = Test::MockModule->new('PVE::Network::SDN::Vnets');
    $vnets_module->mock(
        add_next_free_cidr => sub {
            my ($bridge, $hostname, $mac) = @_;
            push @sdn_calls, 'add';
            $ipam->{$bridge}->{$mac} = $hostname;
        },
        del_ips_from_mac => sub {
            my ($bridge, $mac) = @_;
            push @sdn_calls, 'del';
            delete $ipam->{$bridge}->{$mac};
        },
    );
    my $mocked_destroy = PVE::LXC->can('destroy_lxc_container');
    my $with_ipam = {
        delete_ifaces_ipams_ips => $lxc_module->original('delete_ifaces_ipams_ips'),
        destroy_lxc_container => sub {
            my ($storecfg, $vmid, $conf) = @_;
            # like the real function, which removes the addresses of the old container
            PVE::LXC::delete_ifaces_ipams_ips($conf, $vmid);
            return $mocked_destroy->(@_);
        },
    };
    my $run = sub($setup, $call) {
        reset_state();
        $setup->();
        (@sdn_calls, $ipam) = ();
        $ipam = { vnet0 => { $mac => 'existing' } } if defined(read_raw_config(200));
        return with_mock($lxc_module, $with_ipam, $call);
    };
    my $existing = sub { write_raw_config(200, $existing_raw) };
    my $restore = sub { restore_ct(200, { force => 1, net0 => $net }) };

    my $err =
        $run->(sub { $existing->(); $backup_read_error = "unable to read backup\n"; }, $restore);
    like($err, qr/unable to read backup/, 'restore fails before it replaces the container');
    is_deeply(\@sdn_calls, [], 'IPAM is not touched');
    ok(exists($ipam->{vnet0}->{$mac}), 'the container keeps its IPAM mapping');

    is($run->($existing, $restore), '', 'restore succeeds') or diag($task_log);
    is_deeply(
        \@sdn_calls,
        ['del', 'add'],
        'the option is applied once the old container is removed',
    );
    ok(exists($ipam->{vnet0}->{$mac}), 'the restored interface has an IPAM mapping');

    $err = $run->(
        sub { $in_between = $existing },
        sub {
            my $stale_guest_list = { check_vmid_unused => sub { return 1 } };
            my $create = sub { create_ct(200, { net0 => $net }) };
            return with_mock($cluster_module, $stale_guest_list, $create);
        },
    );
    like($err, qr/CT 200 already exists/, 'create does not get the VMID');
    is_deeply(\@sdn_calls, [], 'IPAM is not touched');

    is($run->(sub { }, sub { create_ct(200, { net0 => $net }) }), '', 'create succeeds')
        or diag($task_log);
    is_deeply(\@sdn_calls, ['add'], 'the option is applied');
    like(PVE::LXC::Config->load_config(200)->{net0}, qr/hwaddr=$mac/, 'and is in the config');
};

remove_tree($WORKDIR);

done_testing();
