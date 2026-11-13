#!/usr/bin/perl

# Runs API calls that create, restore, update and migrate containers against a fake cluster
# filesystem in a working directory, with storage and container runtime operations mocked.

use v5.36;

use lib qw(..);

# Modules of pve-ha-manager and pve-manager are not build dependencies, so stub the ones that the
# tested modules load. Tests that call into them mock the functions they need.
BEGIN {
    $INC{'PVE/HA/Config.pm'} = $INC{'PVE/HA/Env/PVE2.pm'} = __FILE__;
    $INC{'PVE/VZDump.pm'} = __FILE__;
}

use Fcntl qw(:flock);
use File::Path qw(make_path remove_tree);
use JSON;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test::MockModule;
use Test::More;

use PVE::Cluster;
use PVE::GuestHelpers;
use PVE::GuestIdentity;
use PVE::INotify;
use PVE::JSONSchema;
use PVE::Tools qw(file_get_contents file_set_contents);

use PVE::CLI::pct;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::LXC::Migrate;

use PVE::API2::LXC;
use PVE::API2::LXC::Config;

my $WORKDIR = 'lifecycle-working';
my $NODENAME = PVE::INotify::nodename();
my $BACKUP_VOLID = 'local:backup/vzdump-lxc-100-2026_01_01-00_00_00.tar.zst';
my $PBS_VOLID = 'pbs:backup/ct/100/2026-01-01T00:00:00Z';
my $BACKUP_META = 'ctime=1400000000,rtime=1400000000000,uid=backupbackupbackupba';
my $EXISTING_META = 'ctime=1500000000,rtime=1500000000000,uid=existingexistingexis';

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

my sub write_raw_vm_config($vmid, $raw) {
    my $dir = cfs_file("nodes/$NODENAME/qemu-server");
    make_path($dir);
    file_set_contents("$dir/$vmid.conf", $raw);
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
        shared => {
            type => 'nfs',
            path => '/mnt/pve/shared',
            shared => 1,
            content => { rootdir => 1, images => 1 },
        },
    },
};

# error of the cluster-wide guest identity lock, if set
my $domain_lock_error;

# reported Proxmox VE versions of the other cluster nodes
my $node_versions = {
    'new-node' => PVE::GuestIdentity::MIN_PVE_MANAGER_VERSION,
    'old-node' => '9.2.0',
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
    cfs_lock_domain => sub {
        my ($domain, $timeout, $code, @param) = @_;
        die "unexpected lock domain '$domain'\n" if $domain ne 'guest-identity';
        if (defined($domain_lock_error)) {
            $@ = $domain_lock_error;
            return undef;
        }
        my $res = eval { $code->(@param) };
        return $res;
    },
    get_guest_config_properties => sub {
        my ($properties) = @_;
        my $res = {};
        for my $file (glob("$WORKDIR/cfs/nodes/*/{lxc,qemu-server}/*.conf")) {
            my ($vmid) = $file =~ m|/(\d+)\.conf$|;
            for my $line (split(/\n/, file_get_contents($file))) {
                last if $line =~ m/^\[/;
                for my $property (@$properties) {
                    # like pmxcfs, a line with nothing after the colon does not count
                    $res->{$vmid}->{$property} = $1 =~ s/^\s+|\s+$//gr
                        if $line =~ m/^\Q$property\E:(.+)$/;
                }
            }
        }
        return $res;
    },
    remote_node_ip => sub { return '192.0.2.1' },
    get_node_pvecfg_version => sub {
        my ($node) = @_;
        return $node_versions->{$node};
    },
    node_pvecfg_version_at_least => sub {
        my ($node, @required) = @_;
        my @version = split(/\./, $node_versions->{$node} // return 0);
        for my $i (0 .. 2) {
            return $version[$i] > $required[$i] if $version[$i] != $required[$i];
        }
        return 1;
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

# guest identities are generated deterministically
my $random_counter = 0;
my $now_ms = 1_700_000_000_000;

my $identity_module = Test::MockModule->new('PVE::GuestIdentity');
$identity_module->mock(
    __random_bytes => sub {
        my ($len) = @_;
        die "unexpected length $len\n" if $len != 20;
        # one byte per uid character, the last three hold 5 bits of the counter each
        my $n = ++$random_counter;
        return ("\0" x 17) . pack('C3', map { ($n >> $_) & 31 } (10, 5, 0));
    },
    __time_ms => sub { return $now_ms },
);

my $repl_config_module = Test::MockModule->new('PVE::ReplicationConfig');
$repl_config_module->mock(
    new => sub { return bless {}, 'PVE::ReplicationConfig' },
    check_for_existing_jobs => sub { return undef },
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
    setup_default_cli_env => sub { },
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
my $volumes_touched = 0;

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
    volume_rollback_is_possible => sub { return 1 },
    volume_snapshot_rollback => sub { },
);

my $lxc_module = Test::MockModule->new('PVE::LXC');
$lxc_module->mock(
    check_running => sub { return 0 },
    create_disks => sub {
        my ($storecfg, $vmid, $settings, $conf, $pending, $allocated) = @_;
        my $vollist = $allocated // [];
        $volumes_touched++;
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
        $volumes_touched++;
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
    copy_volume => sub {
        my ($mp, $newid) = @_;
        return "local:$newid/vm-$newid-disk-0.raw";
    },
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
    sub post_clone_hook { }
}

my $firewall_module = Test::MockModule->new('PVE::Firewall');
$firewall_module->mock(
    clone_vmfw_conf => sub { },
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
    $now_ms = 1_700_000_000_000;
    $domain_lock_error = undef;
    $volumes_touched = 0;
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

my sub update_ct($vmid, $param) {
    return run_task(sub {
        PVE::API2::LXC::Config->update_vm({ node => $NODENAME, vmid => $vmid, $param->%* });
    });
}

my sub clone_ct($vmid, $newid, $param = undef) {
    return run_task(sub {
        PVE::API2::LXC->clone_vm({
            node => $NODENAME,
            vmid => $vmid,
            newid => $newid,
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
    meta: ctime=1600000000
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

# Returns the members of the 'meta' property in the config of $vmid.
my sub meta_of($vmid) {
    my $conf = PVE::LXC::Config->load_config($vmid);

    return { map { split(/=/, $_, 2) } split(/,/, $conf->{meta} // '') };
}

my sub identity_of($vmid) {
    return PVE::LXC::Config->get_identity(PVE::LXC::Config->load_config($vmid));
}

my sub pending_uid_of($vmid) {
    return PVE::GuestIdentity::get_pending_uid(PVE::LXC::Config->load_config($vmid));
}

# Returns whether the config lock of $vmid is held, for mocks of functions that need it.
my sub config_lock_held($vmid) {
    open(my $fh, '>>', "$WORKDIR/lock/pve-config-$vmid.lock") or die "open failed - $!\n";

    return !flock($fh, LOCK_EX | LOCK_NB);
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

subtest 'only a restore over an existing container destroys the old one' => sub {
    my $destroyed = 0;
    my $mocked_destroy = PVE::LXC->can('destroy_lxc_container');
    my $count = {
        destroy_lxc_container => sub {
            $destroyed++;
            return $mocked_destroy->(@_);
        },
    };

    reset_state();
    my $err = with_mock($lxc_module, $count, sub { restore_ct(200) });
    is($err, '', 'restore to an unused VMID succeeds') or diag($task_log);
    is($destroyed, 0, 'it does not destroy anything');

    reset_state();
    $err = with_mock($lxc_module, $count, sub { create_ct(200) });
    is($err, '', 'create succeeds') or diag($task_log);
    is($destroyed, 0, 'create does not destroy anything');

    reset_state();
    write_raw_config(200, existing_config());
    $err = with_mock($lxc_module, $count, sub { restore_ct(200, { force => 1 }) });
    is($err, '', 'restore over an existing container succeeds') or diag($task_log);
    is($destroyed, 1, 'it destroys the old container');
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

subtest 'migration tunnel waits for a volume transfer before it cleans up' => sub {
    # the volume of a transfer is only known once the transfer is done
    my $import_cmd = {
        cmd => 'disk-import',
        volname => 'vm-300-disk-0',
        format => 'raw',
        export_formats => 'raw+size',
        storage => 'local',
    };

    reset_state();
    my $no_format =
        { volume_import_start => sub { die "no matching import/export format found\n" } };
    my ($err, $replies) =
        with_mock($storage_module, $no_format, sub { [run_mtunnel(300, $import_cmd)] })->@*;
    ok(!$replies->[0]->{success}, 'volume transfer that fails to start')
        or diag(explain($replies));
    unlike($task_log, qr/still running/, 'it is not taken as running');
    ok(!defined(read_raw_config(300)), 'reserved config is removed after it');

    # the clock advances with each wait for the transfer
    my ($now, $queries) = (0, 0);
    my $time_module = Test::MockModule->new('Time::HiRes');
    $time_module->mock(
        time => sub { return $now },
        usleep => sub {
            $now += $_[0] / 1_000_000;
            die "the wait does not end\n" if $now > 120;
        },
    );
    my $storage_tunnel_module = Test::MockModule->new('PVE::StorageTunnel');
    $storage_tunnel_module->mock(
        handle_disk_import => sub {
            my ($state) = @_;
            $state->{disk_import} = { pid => 1 };
            return {};
        },
        handle_query_disk_import => sub {
            $queries++;
            return { status => 'pending' };
        },
    );
    reset_state();
    ($err, $replies) = run_mtunnel(300, $import_cmd);
    like(
        $task_log,
        qr/^WARN: cleanup failed - a volume transfer is still running$/m,
        'transfer that does not end is reported',
    );
    ok($queries > 0, 'the transfer got queried');
    ok(defined(read_raw_config(300)), 'reserved config is kept while a transfer still runs');
};

subtest 'post-stop hook only changes the config under its lock' => sub {
    my $while_hook_runs;
    my $lxc_config_memory; # the memory setting that the lxc config got written with last
    $lxc_module->mock(
        get_staging_tempfs => sub { return "$WORKDIR/staging" },
        vm_stop_cleanup => sub { $while_hook_runs->() if $while_hook_runs },
        update_lxc_config => sub($vmid, $conf) { $lxc_config_memory = $conf->{memory} },
    );
    my $tools_module = Test::MockModule->new('PVE::Tools');
    $tools_module->mock(run_command => sub { });
    my $guest_helpers_module = Test::MockModule->new('PVE::GuestHelpers');
    $guest_helpers_module->mock(exec_hookscript => sub { });
    # the hook runs several times in this process
    $restenv_module->mock(setup_default_cli_env => sub { });
    # a build environment has no syslog socket, which makes setting up the log warn
    my $lxc_tools_module = Test::MockModule->new('PVE::LXC::Tools');
    $lxc_tools_module->mock(initlog => sub { });

    local $ENV{LXC_HOOK_VERSION} = '1';
    local $ENV{LXC_NAME} = '200';
    local $ENV{LXC_HOOK_SECTION} = 'lxc';
    local $ENV{LXC_HOOK_TYPE} = 'post-stop';
    local $ENV{LXC_ROOTFS_MOUNT} = "$WORKDIR/rootfs/200";
    local $ENV{LXC_ROOTFS_PATH} = "$WORKDIR/rootfs/200";
    local $ENV{LXC_CONFIG_FILE} = "$WORKDIR/lxc-200.config";
    delete local $ENV{LXC_TARGET};

    my $run_hook = sub {
        my $err = run_task(sub {
            do '../lxc-pve-poststop-hook';
            die $@ if $@;
        });
        is($err, '', 'hook succeeds') or diag($task_log);
        unlike($task_log, qr/WARN/, 'hook does not warn') or diag($task_log);
    };
    my $pending = existing_config() . "\n[pve:pending]\nmemory: 1024\n";

    reset_state();
    write_raw_config(200, existing_config());
    $run_hook->();
    ok(!$written->{200}, 'without pending changes: config is not written');

    # another process changes the config after the hook loaded it
    reset_state();
    write_raw_config(200, $pending);
    $while_hook_runs = sub {
        PVE::LXC::Config->lock_config(
            200,
            sub {
                my $conf = PVE::LXC::Config->load_config(200);
                $conf->{description} = 'changed while the hook ran';
                PVE::LXC::Config->write_config(200, $conf);
            },
        );
    };
    $run_hook->();
    my $conf = PVE::LXC::Config->load_config(200);
    is($conf->{memory}, 1024, 'lock is free: pending change is applied');
    is_deeply($conf->{pending}, {}, 'lock is free: no pending change is left');
    like(
        $conf->{description},
        qr/^changed while the hook ran$/,
        'lock is free: other change is kept',
    );
    is($lxc_config_memory, 1024, 'lock is free: lxc config has the applied change');

    # Another process, like a task that stops the container, holds the lock while the hook runs.
    # A handle of its own conflicts with the lock of this process in the same way.
    reset_state();
    write_raw_config(200, $pending);
    $while_hook_runs = undef;
    my $lockfile = PVE::LXC::Config->config_file_lock(200);
    open(my $other, '>>', $lockfile) or die "unable to open '$lockfile' - $!\n";
    flock($other, LOCK_EX) or die "unable to lock '$lockfile' - $!\n";
    $lxc_config_memory = undef;
    $run_hook->();
    ok(!$written->{200}, 'lock is held: hook does not write the config');
    ok(!defined($lxc_config_memory), 'lock is held: hook does not write the lxc config');
    close($other);

    # what vm_stop does once the container has stopped
    $conf = PVE::LXC::Config->lock_config(200, sub { PVE::LXC::apply_pending_after_stop(200) });
    is($conf->{memory}, 1024, 'lock is held: its holder gets the changed config');
    like(
        read_raw_config(200),
        qr/^memory: 1024$/m,
        'lock is held: its holder applied the change',
    );
    unlike(read_raw_config(200), qr/pending/, 'lock is held: no pending change is left');
    is($lxc_config_memory, 1024, 'lock is held: its holder writes the lxc config');

    $lxc_module->unmock('get_staging_tempfs', 'vm_stop_cleanup');
    $lxc_module->mock(update_lxc_config => sub { });
    $restenv_module->unmock('setup_default_cli_env');
};

subtest 'restore treats a container that got removed before the reservation as new' => sub {
    my $removed_in_between = sub($raw) {
        reset_state();
        write_raw_config(200, $raw);
        $in_between = sub { PVE::LXC::Config->destroy_config(200) };
    };

    $removed_in_between->(existing_config());
    $backup_read_error = "unable to read backup\n";
    like(restore_ct(200, { force => 1 }), qr/unable to read backup/, 'early failure: fails');
    ok(!defined(read_raw_config(200)), 'early failure: the VMID is released');

    # overwriting a privileged container with a privileged one needs no 'Sys.Modify', creating
    # one does
    my $privileged = sub($raw) { return $raw =~ s/^unprivileged: 1\n//mr };
    $removed_in_between->($privileged->(existing_config()));
    $backup_raw_config = $privileged->(backup_config());
    my $deny = { '/' => { 'Sys.Modify' => 1 } };
    my $err = as_user('user@pve', $deny, sub { restore_ct(200, { force => 1 }) });
    like(
        $err,
        qr/permission check failed \(\/, Sys\.Modify\)/,
        'privileged: restore is refused',
    );
    ok(!defined(read_raw_config(200)), 'privileged: the VMID is released');
};

subtest 'meta cannot be changed through the API' => sub {
    reset_state();
    write_raw_config(200, existing_config('ctime=1500000000'));
    my $raw = read_raw_config(200);

    for my $user ('root@pam', 'admin@pve') {
        my $rejected = sub($name, $expected_err, $call) {
            like(as_user($user, {}, $call), $expected_err, "$user cannot $name");
        };
        my $unknown = qr/meta: property is not defined in schema/;
        $rejected->('set meta', $unknown, sub { update_ct(200, { meta => 'ctime=1' }) });
        $rejected->('create with meta', $unknown,
            sub { create_ct(201, { meta => 'ctime=1' }) });
        $rejected->(
            'restore with meta',
            $unknown,
            sub { restore_ct(200, { force => 1, meta => 'ctime=1' }) },
        );
        $rejected->(
            'delete meta',
            qr/unable to delete read-only option: 'meta'/,
            sub { update_ct(200, { delete => 'meta' }) },
        );
        $rejected->(
            'revert meta',
            qr/unable to revert read-only option: 'meta'/,
            sub { update_ct(200, { revert => 'meta' }) },
        );
    }

    is(read_raw_config(200), $raw, 'config is unchanged');
    ok(!defined(read_raw_config(201)), 'no container got created');

    my $conf = PVE::LXC::Config->load_config(200);
    eval { PVE::LXC::Config->update_pct_config(200, $conf, 0, { meta => 'ctime=1' }, [], []) };
    like($@, qr/unable to modify read-only option: 'meta'/, 'update cannot set meta');

    write_raw_config(200, existing_config());
    my $err = update_ct(200, { delete => 'meta' });
    like($err, qr/unable to delete read-only option: 'meta'/,
        'meta cannot be deleted if unset');
};

subtest 'pending changes of meta are dropped' => sub {
    my $raw = existing_config('ctime=1500000000') . <<~'EOF';

        [pve:pending]
        delete: meta
        meta: ctime=1
        EOF

    reset_state();
    write_raw_config(200, $raw);
    my $err = update_ct(200, { hostname => 'changed' });
    is($err, '', 'update succeeds');
    like($task_log, qr/ignoring pending change of read-only option 'meta'/, 'drop is logged');
    my $conf = PVE::LXC::Config->load_config(200);
    is(meta_of(200)->{ctime}, 1500000000, 'ctime is kept');
    is_deeply($conf->{pending}, {}, 'pending change of meta is dropped');

    for my $pending ('meta: ctime=1', 'delete: meta') {
        $conf = PVE::LXC::Config::parse_pct_config(
            '/lxc/200.conf',
            existing_config('ctime=1500000000') . "\n[pve:pending]\n$pending\n",
        );
        {
            local $SIG{__WARN__} = sub { };
            PVE::LXC::Config->vmconfig_apply_pending(200, $conf, $storage_cfg);
        }
        is($conf->{meta}, 'ctime=1500000000', "applying '$pending' keeps meta");
        is_deeply($conf->{pending}, {}, "applying drops '$pending'");
    }

    $conf = PVE::LXC::Config::parse_pct_config('/lxc/200.conf', $raw);
    my $cgroup_module = Test::MockModule->new('PVE::LXC::CGroup');
    $cgroup_module->mock(new => sub { return bless {}, 'PVE::LXC::CGroup' });
    with_mock(
        $lxc_module,
        { find_lxc_pid => sub { return 1 } },
        sub {
            local $SIG{__WARN__} = sub { };
            PVE::LXC::Config->vmconfig_hotplug_pending(200, $conf, $storage_cfg, undef, {});
        },
    );
    is($conf->{meta}, 'ctime=1500000000', 'hotplugging keeps meta');
    is_deeply($conf->{pending}, {}, 'hotplugging drops the pending change of meta');
};

subtest 'meta with members unknown to this version can be read' => sub {
    reset_state();
    write_raw_config(200, existing_config('ctime=1500000000,future=value'));

    my $info = PVE::API2::LXC::Config->map_method_by_name('vm_config');
    my $conf = eval {
        local $SIG{__WARN__} = sub { };
        PVE::API2::LXC::Config->handle($info, { node => $NODENAME, vmid => 200 }, 1);
    };
    is($@, '', 'config passes the result verification');
    is($conf->{meta}, 'ctime=1500000000,future=value', 'meta is returned as it is');
};

subtest 'create sets the creation time, restore and remote migration keep it' => sub {
    reset_state();

    my $before = time();
    my $err = create_ct(201);
    my $after = time();
    is($err, '', 'create succeeds');
    my $ctime = meta_of(201)->{ctime};
    ok($ctime >= $before && $ctime <= $after, 'ctime is the time of the create');

    $backup_raw_config = backup_config('ctime=1400000000');
    $err = restore_ct(202);
    is($err, '', 'restore to an unused VMID succeeds');
    is(meta_of(202)->{ctime}, 1400000000, 'ctime of the backup is kept');

    write_raw_config(200, existing_config('ctime=1500000000'));
    $err = restore_ct(200, { force => 1 });
    is($err, '', 'restore over an existing container succeeds');
    is(meta_of(200)->{ctime}, 1400000000, 'ctime of the backup is used');

    ($err, my $replies) = run_mtunnel(
        300,
        { cmd => 'config', conf => $INCOMING_CONFIG },
        { cmd => 'quit', cleanup => 0 },
    );
    is($err, '', 'tunnel exits normally') or diag(explain($replies), $task_log);
    is(meta_of(300)->{ctime}, 1600000000, 'ctime of the source of a migration is kept');
    is(PVE::LXC::Config->load_config(300)->{hostname}, 'incoming', 'with its other options');
};

subtest 'create assigns a new guest identity' => sub {
    reset_configs();
    $now_ms = 1_700_000_000_000;

    my $err = create_ct(201);
    is($err, '', 'create succeeds');

    my $meta = meta_of(201);
    like($meta->{uid}, qr/^[a-z2-7]{20}$/, 'uid is assigned');
    is($meta->{rtime}, 1_700_000_000_000, 'rtime is the time of the create');
    ok(defined($meta->{ctime}), 'ctime is kept next to the identity');
    ok(!defined(PVE::LXC::Config->load_config(201)->{lock}), 'create lock is removed');

    $err = create_ct(202);
    isnt(identity_of(202)->{uid}, $meta->{uid}, 'another container gets another uid');
};

subtest 'config changes keep the guest identity' => sub {
    reset_configs();
    my $meta = 'ctime=1500000000,rtime=1500000000000,uid=existingexistingexis';
    write_raw_config(200, existing_config($meta));
    $now_ms = 1_700_000_000_000;

    my $err = update_ct(200, { hostname => 'changed', memory => 1024 });
    is($err, '', 'update succeeds');
    my $conf = PVE::LXC::Config->load_config(200);
    is($conf->{hostname}, 'changed', 'change is applied');
    is($conf->{meta}, $meta, 'meta is unchanged');

    write_raw_config(200, existing_config('ctime=1500000000'));
    $err = update_ct(200, { hostname => 'first-write' });
    is($err, '', 'update of a container without identity succeeds');
    my $identity = identity_of(200);
    like($identity->{uid}, qr/^[a-z2-7]{20}$/, 'first write assigns a uid');
    is($identity->{rtime}, 1_700_000_000_000, 'first write sets rtime');
    is(meta_of(200)->{ctime}, 1500000000, 'ctime is kept');

    $now_ms += 1000;
    $err = update_ct(200, { hostname => 'second-write' });
    is_deeply(identity_of(200), $identity, 'later writes keep the identity');
};

subtest 'clone assigns a new guest identity' => sub {
    reset_configs();
    write_raw_config(
        200,
        existing_config('ctime=1500000000,rtime=1500000000000,uid=existingexistingexis'),
    );
    $now_ms = 1_700_000_000_000;

    my $err = clone_ct(200, 201, { hostname => 'clone' });
    is($err, '', 'clone succeeds') or diag($task_log);

    my $meta = meta_of(201);
    like($meta->{uid}, qr/^[a-z2-7]{20}$/, 'clone has a uid');
    isnt($meta->{uid}, 'existingexistingexis', 'clone does not get the uid of the source');
    is($meta->{rtime}, 1_700_000_000_000, 'rtime is the time of the clone');
    is($meta->{ctime}, 1500000000, 'ctime of the source is kept');
    is(identity_of(200)->{uid}, 'existingexistingexis', 'source keeps its uid');
};

subtest 'snapshot rollback keeps the current guest identity' => sub {
    reset_configs();
    write_raw_config(200, <<~'EOF');
        arch: amd64
        hostname: existing
        memory: 512
        meta: ctime=1500000000,rtime=1600000000000,uid=existingexistingexis
        ostype: debian
        parent: snap
        rootfs: local:200/vm-200-disk-0.raw,size=4G
        unprivileged: 1

        [snap]
        arch: amd64
        hostname: snapshot
        memory: 512
        meta: ctime=1500000000,rtime=1500000000000,uid=snapshotsnapshotsnap
        ostype: debian
        rootfs: local:200/vm-200-disk-0.raw,size=4G
        snaptime: 1500000000
        unprivileged: 1
        EOF

    my $err = run_task(sub { PVE::LXC::Config->snapshot_rollback(200, 'snap') });
    is($err, '', 'rollback succeeds') or diag($task_log);

    my $conf = PVE::LXC::Config->load_config(200);
    is($conf->{hostname}, 'snapshot', 'config of the snapshot is restored');
    is_deeply(
        identity_of(200),
        { uid => 'existingexistingexis', rtime => 1600000000000 },
        'current identity is kept',
    );
};

subtest 'in-place restore keeps the guest identity of the target' => sub {
    reset_configs();
    my $meta = 'ctime=1500000000,rtime=1500000000000,uid=existingexistingexis';
    write_raw_config(200, existing_config($meta));

    for my $backup_meta (
        undef, 'ctime=1400000000,rtime=1400000000000,uid=existingexistingexis',
    ) {
        $backup_raw_config = backup_config($backup_meta);
        my $err = restore_ct(200, { force => 1 });
        is($err, '', 'restore succeeds') or diag($task_log);
        is_deeply(
            identity_of(200),
            { uid => 'existingexistingexis', rtime => 1500000000000 },
            'identity is kept',
        );
        is(PVE::LXC::Config->load_config(200)->{hostname}, 'backup', 'backup is restored');
    }
};

subtest 'backup assigns the guest identity and includes it' => sub {
    reset_configs();
    write_raw_config(987, existing_config('ctime=1500000000'));
    $now_ms = 1_700_000_000_000;

    require PVE::VZDump::LXC;
    my $plugin = bless { vzdump => { opts => { pbs => 1 } } }, 'PVE::VZDump::LXC';

    $plugin->lock_vm(987);
    my $identity = identity_of(987);
    like($identity->{uid}, qr/^[a-z2-7]{20}$/, 'backup lock assigns a uid');
    is($identity->{rtime}, $now_ms, 'backup lock sets rtime');

    $plugin->assemble({ tmpdir => "$WORKDIR/backup" }, 987);
    my $raw = file_get_contents("$WORKDIR/backup/etc/vzdump/pct.conf");
    my $backup_conf = PVE::LXC::Config::parse_pct_config('/lxc/987.conf', $raw);
    is_deeply(
        PVE::LXC::Config->get_identity($backup_conf),
        $identity,
        'backup has the identity',
    );

    $now_ms += 1000;
    $plugin->unlock_vm(987);
    is_deeply(identity_of(987), $identity, 'removing the backup lock keeps the identity');
};

subtest 'migration is refused to nodes that drop the guest identity' => sub {
    reset_configs();
    my $raw = existing_config('ctime=1500000000,rtime=1500000000000,uid=existingexistingexis');
    write_raw_config(200, $raw);

    my $migrated_to;
    my $migrate_module = Test::MockModule->new('PVE::LXC::Migrate');
    $migrate_module->mock(migrate => sub { $migrated_to = $_[1] });
    my $ha_config_module = Test::MockModule->new('PVE::HA::Config');
    $ha_config_module->mock(vm_is_ha_managed => sub { return 0 });

    my $migrate = sub {
        my ($target, $param) = @_;
        return run_task(sub {
            PVE::API2::LXC->migrate_vm({
                node => $NODENAME,
                vmid => 200,
                target => $target,
                ($param // {})->%*,
            });
        });
    };

    my $err = $migrate->('old-node');
    like($err, qr/node 'old-node' runs Proxmox VE 9\.2\.0/, 'node too old is refused');
    $err = $migrate->('unknown-node');
    like($err, qr/does not report its Proxmox VE version/, 'node without version is refused');

    my $stopped = 0;
    $lxc_module->mock(
        check_running => sub { return 1 },
        vm_stop => sub { $stopped = 1 },
    );
    $err = $migrate->('old-node', { restart => 1 });
    $lxc_module->mock(check_running => sub { return 0 });
    $lxc_module->unmock('vm_stop');
    like($err, qr/node 'old-node' runs Proxmox VE 9\.2\.0/, 'restart migration is refused');
    ok(!$stopped, 'running container is not stopped');

    ok(!defined($migrated_to), 'migration does not start');
    is(read_raw_config(200), $raw, 'config is unchanged');

    $err = $migrate->('new-node');
    is($err, '', 'migration to an upgraded node starts');
    is($migrated_to, 'new-node', 'migration goes to the target');
};

subtest 'migration preconditions list nodes that drop the guest identity' => sub {
    reset_configs();
    my $raw = existing_config('ctime=1500000000,rtime=1500000000000,uid=existingexistingexis');
    write_raw_config(200, $raw);

    my $ha_config_module = Test::MockModule->new('PVE::HA::Config');
    $ha_config_module->mock(vm_is_ha_managed => sub { return 0 });
    $cluster_module->mock(
        get_nodelist => sub { return [$NODENAME, 'new-node', 'old-node', 'unknown-node'] },
    );

    my $res = PVE::API2::LXC->migrate_vm_precondition({ node => $NODENAME, vmid => 200 });
    $cluster_module->unmock('get_nodelist');

    my $required = PVE::GuestIdentity::MIN_PVE_MANAGER_VERSION;
    is_deeply($res->{'allowed-nodes'}, ['new-node'], 'only the upgraded node is allowed');
    is_deeply(
        $res->{'not-allowed-nodes'},
        {
            'old-node' => {
                'guest-identity-unsupported' => {
                    version => '9.2.0',
                    'required-version' => $required,
                },
            },
            'unknown-node' => {
                'guest-identity-unsupported' => { 'required-version' => $required },
            },
        },
        'nodes that drop the identity are not allowed',
    );

    my $returns = PVE::API2::LXC->map_method_by_name('migrate_vm_precondition')->{returns};
    eval { PVE::JSONSchema::validate($res, $returns) };
    is($@, '', 'result matches the schema');
    my $reasons_schema = {
        $returns->{properties}->{'not-allowed-nodes'}->{additionalProperties}->%*,
        additionalProperties => 0,
    };
    for my $node ('old-node', 'unknown-node') {
        my $reasons = $res->{'not-allowed-nodes'}->{$node};
        eval { PVE::JSONSchema::validate($reasons, $reasons_schema) };
        is($@, '', "reason for $node is documented in the schema");
    }
};

subtest 'clone feature only lists nodes that keep the guest identity' => sub {
    reset_configs();
    my $raw = existing_config('ctime=1500000000,rtime=1500000000000,uid=existingexistingexis');
    write_raw_config(200, $raw);

    $config_module->mock(has_feature => sub { return 1 });
    $cluster_module->mock(
        get_nodelist => sub { return [$NODENAME, 'new-node', 'old-node', 'unknown-node'] },
    );

    my $res =
        PVE::API2::LXC->vm_feature({ node => $NODENAME, vmid => 200, feature => 'clone' });
    $cluster_module->unmock('get_nodelist');

    # the local node reports no version here, a clone on the same node needs no check
    is_deeply(
        $res->{nodes},
        [$NODENAME, 'new-node'],
        'nodes that drop the identity are left out',
    );

    my $returns = PVE::API2::LXC->map_method_by_name('vm_feature')->{returns};
    eval { PVE::JSONSchema::validate($res, $returns) };
    is($@, '', 'result matches the schema');

    my $lookups = 0;
    my $mocked_at_least = \&PVE::Cluster::node_pvecfg_version_at_least;
    my $mocked_version = \&PVE::Cluster::get_node_pvecfg_version;
    $cluster_module->mock(
        get_nodelist => sub { return [$NODENAME, 'new-node', 'old-node', 'unknown-node'] },
        node_pvecfg_version_at_least => sub { $lookups++; return $mocked_at_least->(@_) },
        get_node_pvecfg_version => sub { $lookups++; return $mocked_version->(@_) },
    );
    $res =
        PVE::API2::LXC->vm_feature({ node => $NODENAME, vmid => 200, feature => 'snapshot' });
    $cluster_module->mock(
        node_pvecfg_version_at_least => $mocked_at_least,
        get_node_pvecfg_version => $mocked_version,
    );
    $cluster_module->unmock('get_nodelist');
    is($lookups, 0, 'snapshot feature: no node versions are looked up');
    ok(!exists($res->{nodes}), 'snapshot feature: no nodes are returned');
    eval { PVE::JSONSchema::validate($res, $returns) };
    is($@, '', 'snapshot feature: result matches the schema');

    $config_module->unmock('has_feature');
};

subtest 'clone to another node is refused if the node drops the guest identity' => sub {
    reset_configs();
    my $raw = <<~'EOF';
        arch: amd64
        hostname: existing
        memory: 512
        meta: ctime=1500000000,rtime=1500000000000,uid=existingexistingexis
        ostype: debian
        rootfs: shared:200/vm-200-disk-0.raw,size=4G
        unprivileged: 1
        EOF
    write_raw_config(200, $raw);
    make_path(cfs_file("nodes/new-node/lxc"));

    my $err = clone_ct(200, 201, { target => 'old-node' });
    like($err, qr/node 'old-node' runs Proxmox VE 9\.2\.0/, 'clone is refused');
    is(read_raw_config(200), $raw, 'source is unchanged');
    ok(!defined(read_raw_config(201)), 'no clone is created');

    $err = clone_ct(200, 201, { target => 'new-node' });
    is($err, '', 'clone to an upgraded node succeeds') or diag($task_log);
    my $clone_raw = read_raw_config(201, 'new-node');
    ok(defined($clone_raw), 'clone is moved to the target node');
    my $identity =
        PVE::GuestIdentity::parse_identity($clone_raw =~ m/^meta: (.*)$/m ? $1 : undef);
    like($identity->{uid}, qr/^[a-z2-7]{20}$/, 'clone has a uid');
    isnt($identity->{uid}, 'existingexistingexis', 'clone has a new uid');
};

subtest 'restore adopts the guest identity of the backup' => sub {
    my $in_use =
        "guest identity: backup uid backupbackupbackupba is in use by guest 150, keeping uid ";
    my $adopted = qr/^guest identity: adopted uid backupbackupbackupba from the backup$/m;
    my $new = qr/^guest identity: new uid [a-z2-7]{20}$/m;

    my $now = 1_700_000_000_000;

    my $locked = 1;
    my $adopt = PVE::GuestIdentity->can('adopt');
    my $probe_lock = {
        adopt => sub {
            my ($class, $vmid) = @_;
            $locked &&= config_lock_held($vmid);
            return $adopt->(@_);
        },
    };

    my $run = sub($name, $setup, $param, $expected_uid, $expected_rtime, $expected_log) {
        reset_state();
        $backup_raw_config = backup_config($BACKUP_META);
        $setup->();
        my $err = with_mock($identity_module, $probe_lock, sub { restore_ct(200, $param) });
        is($err, '', "$name: restore succeeds") or diag($task_log);
        my $identity = identity_of(200);
        if (defined($expected_uid)) {
            is($identity->{uid}, $expected_uid, "$name: uid");
        } else {
            like($identity->{uid}, qr/^[a-z2-7]{20}$/, "$name: uid is assigned");
            isnt(
                $identity->{uid},
                'backupbackupbackupba',
                "$name: uid is not the one of the backup",
            );
        }
        is($identity->{rtime}, $expected_rtime, "$name: rtime");
        like($task_log, $expected_log, "$name: result is logged");
    };
    my $without_identity = sub { write_raw_config(200, existing_config('ctime=1500000000')) };
    my $same_identity = sub {
        write_raw_config(
            200,
            existing_config($EXISTING_META =~ s/uid=.*/uid=backupbackupbackupba/r),
        );
    };
    my $kept = qr/^guest identity: kept uid backupbackupbackupba$/m;
    my $stdin = { ostemplate => '-', rootfs => 'local:4' };

    $run->('unused VMID', sub { }, {}, 'backupbackupbackupba', $now, $adopted);
    $run->(
        'unused VMID, uid used by another container',
        sub { write_raw_config(150, existing_config('uid=backupbackupbackupba')) },
        {},
        undef,
        $now,
        qr/^\Q$in_use\E[a-z2-7]{20}$/m,
    );
    $run->('unused VMID, unique', sub { }, { unique => 1 }, undef, $now, $new);
    $run->(
        'unused VMID, backup without identity',
        sub { $backup_raw_config = backup_config('ctime=1400000000') },
        {},
        undef,
        $now,
        $new,
    );
    $run->(
        'unused VMID, from STDIN', sub { }, $stdin, 'backupbackupbackupba', $now, $adopted,
    );
    $run->(
        'unused VMID, from STDIN without config',
        sub { $backup_raw_config = undef },
        $stdin,
        undef,
        $now,
        $new,
    );
    $run->(
        'in place, container without identity',
        $without_identity,
        { force => 1 },
        'backupbackupbackupba',
        $now,
        $adopted,
    );
    $run->(
        'in place, container without identity, unique',
        $without_identity,
        { force => 1, unique => 1 },
        undef,
        $now,
        $new,
    );
    $run->(
        'in place, container with the same identity',
        $same_identity,
        { force => 1 },
        'backupbackupbackupba',
        1500000000000,
        $kept,
    );
    $run->(
        'in place, container with the same identity, unique',
        $same_identity,
        { force => 1, unique => 1 },
        'backupbackupbackupba',
        1500000000000,
        $kept,
    );
    $run->(
        'in place, container with identity, backup without identity',
        sub {
            write_raw_config(200, existing_config($EXISTING_META));
            $backup_raw_config = backup_config('ctime=1400000000');
        },
        { force => 1 },
        'existingexistingexis',
        1500000000000,
        qr/^guest identity: kept uid existingexistingexis$/m,
    );
    $run->(
        'in place, by a user with only VM.Backup',
        sub {
            $without_identity->();
            $rpcenv = PVE::LXC::Test::RPCEnvironment->new('user@pve');
            $rpcenv->{deny} = { '/vms/200' => { 'VM.Allocate' => 1 } };
        },
        { force => 1 },
        'backupbackupbackupba',
        $now,
        $adopted,
    );

    ok($locked, 'config lock is held while adopting the identity');
};

# Restores over a container without identity and fails after reading the backup. That leaves the
# container behind with the uid of the backup as pending uid.
my sub failed_restore_in_place($param = {}) {
    reset_state();
    $backup_raw_config = backup_config($BACKUP_META);
    write_raw_config(200, existing_config('ctime=1500000000'));
    my $full = { create_disks => sub { die "unable to allocate volume - storage full\n" } };
    my $err = with_mock($lxc_module, $full, sub { restore_ct(200, { force => 1, $param->%* }) });
    like($err, qr/storage full/, 'restore fails after reading the backup');
    is(PVE::LXC::Config->load_config(200)->{hostname}, 'existing', 'container is kept');
    is(pending_uid_of(200), 'backupbackupbackupba', 'it has the uid of the backup as pending uid');
}

subtest 'retry of a failed restore adopts the uid of the backup' => sub {
    reset_state();
    $backup_raw_config = backup_config($BACKUP_META);
    $hook_error = "setup hook failed\n";
    like(restore_ct(200), qr/setup hook failed/, 'restore to an unused VMID fails');
    ok(!defined(read_raw_config(200)), 'its config is removed');
    $hook_error = undef;
    is(restore_ct(200), '', 'retry succeeds') or diag($task_log);
    is(identity_of(200)->{uid}, 'backupbackupbackupba', 'retry adopts the uid');

    failed_restore_in_place();
    isnt(identity_of(200)->{uid}, 'backupbackupbackupba', 'container has a uid of its own');
    is(restore_ct(200, { force => 1 }), '', 'retry over the container succeeds')
        or diag($task_log);
    is(identity_of(200)->{uid}, 'backupbackupbackupba', 'retry adopts the uid');
    is(pending_uid_of(200), undef, 'pending uid is removed');
};

subtest 'retry elsewhere, then over the container left behind' => sub {
    failed_restore_in_place();
    my $leftover = identity_of(200)->{uid};

    my $err = restore_ct(201);
    is($err, '', 'restore to another VMID succeeds') or diag($task_log);
    is(identity_of(201)->{uid}, 'backupbackupbackupba', 'pending uid is not in use');
    is(pending_uid_of(200), 'backupbackupbackupba', 'container left behind keeps it');

    $err = restore_ct(200, { force => 1 });
    is($err, '', 'restore over the container left behind succeeds') or diag($task_log);
    like(
        $task_log,
        qr/: backup uid backupbackupbackupba is in use by guest 201, keeping uid $leftover$/m,
        'uid of the backup is in use by now',
    );
    is(identity_of(200)->{uid}, $leftover, 'container left behind keeps its uid');
    is(pending_uid_of(200), undef, 'pending uid is removed');
};

subtest 'using the container left behind drops its pending uid' => sub {
    failed_restore_in_place();

    my $err = update_ct(200, { description => 'used' });
    is($err, '', 'config change of the stopped container') or diag($task_log);
    my $dropped = "guest identity: dropping pending uid backupbackupbackupba of an unfinished"
        . " restore - a retry now needs 'allow-identity-mismatch'";
    like($task_log, qr/^WARN: \Q$dropped\E$/m, 'dropped');
    is(pending_uid_of(200), undef, 'pending uid is gone');

    $err = restore_ct(200, { force => 1 });
    like($err, qr/backup belongs to another guest/, 'container stays a guest of its own');
};

subtest 'restore with unique keeps a pending uid, but never adopts it' => sub {
    for my $retry ({ unique => 1 }, {}) {
        my $what = $retry->{unique} ? 'retry with unique' : 'retry without unique';

        failed_restore_in_place({ unique => 1 });
        my $leftover = identity_of(200)->{uid};

        my $err = restore_ct(200, { force => 1, $retry->%* });
        is($err, '', "$what succeeds") or diag($task_log);
        is(pending_uid_of(200), undef, "$what: pending uid is removed");
        is(
            identity_of(200)->{uid},
            $retry->{unique} ? $leftover : 'backupbackupbackupba',
            "$what: " . ($retry->{unique} ? 'keeps its uid' : 'adopts the uid of the backup'),
        );
    }
};

subtest 'failed adoption keeps the pending uid' => sub {
    reset_state();
    $backup_raw_config = backup_config($BACKUP_META);
    $domain_lock_error = "cfs-lock 'domain-guest-identity' error: no quorum!\n";
    my $err = restore_ct(200);
    $domain_lock_error = undef;
    is($err, '', 'restore succeeds') or diag($task_log);
    my $uid = identity_of(200)->{uid};
    isnt($uid, 'backupbackupbackupba', 'container has a uid of its own');
    my $warning =
        "WARN: guest identity: unable to adopt backup uid backupbackupbackupba, keeping"
        . " uid $uid - cfs-lock 'domain-guest-identity' error: no quorum!";
    like($task_log, qr/^\Q$warning\E$/m, 'failure is logged as warning');
    is(pending_uid_of(200), 'backupbackupbackupba', 'nothing decided, pending uid stays');

    $err = restore_ct(200, { force => 1 });
    is($err, '', 'restore of the backup again succeeds') or diag($task_log);
    is(identity_of(200)->{uid}, 'backupbackupbackupba', 'uid of the backup is adopted');
};

subtest 'config of a container left behind shows its stored identity' => sub {
    failed_restore_in_place();
    my $meta = PVE::LXC::Config->load_config(200)->{meta};

    my $conf = PVE::API2::LXC::Config->vm_config({ node => $NODENAME, vmid => 200 });
    is($conf->{meta}, $meta, 'config with pending changes applied: stored identity');
    $conf = PVE::API2::LXC::Config->vm_config({ node => $NODENAME, vmid => 200, current => 1 });
    is($conf->{meta}, $meta, 'current config: stored identity');

    my $pending = PVE::API2::LXC->vm_pending({ node => $NODENAME, vmid => 200 });
    my ($item) = grep { $_->{key} eq 'meta' } $pending->@*;
    is($item->{value}, $meta, 'pending view: current value');
    is($item->{pending}, 'uid=backupbackupbackupba', 'pending view: pending uid');
};

# Once a write of the config of CT 200 has the pending uid of the backup, all later writes of the
# restore have it, so that the container keeps it whenever the restore stops. Only the adoption
# removes it.
subtest 'every write of a restore keeps the pending uid' => sub {
    my $cases = [
        ['unused VMID', undef, {}],
        ['in place over a container without uid', existing_config('ctime=1500000000'), {}],
        ['unused VMID, from STDIN', undef, { ostemplate => '-', rootfs => 'local:4' }],
        ['unused VMID, template', undef, {}, "template: 1\n"],
    ];

    for my $case (@$cases) {
        my ($what, $target, $param, $extra) = @$case;

        reset_state();
        $backup_raw_config = backup_config($BACKUP_META) . ($extra // '');
        write_raw_config(200, $target) if $target;
        my $restore = sub { restore_ct(200, { $target ? (force => 1) : (), $param->%* }) };
        my $err =
            with_mock($storage_module, { volume_has_feature => sub { return 0 } }, $restore);
        is($err, '', "$what: restore succeeds") or diag($task_log);
        like(
            $task_log,
            qr/^guest identity: adopted uid backupbackupbackupba/m,
            "$what: adopted",
        );

        my @writes = $written->{200}->@*;
        my $last = pop(@writes);
        my $first = 0;
        $first++ while $first < @writes && $writes[$first] !~ m/^\[pve:pending\]/m;
        ok($first < @writes, "$what: pending uid is written") or next;
        my @later = @writes[$first .. $#writes];
        is(
            scalar(grep { m/^\[pve:pending\]\nmeta: uid=backupbackupbackupba$/m } @later),
            scalar(@later),
            "$what: all later writes keep it",
        );
        unlike($last, qr/^\[pve:pending\]/m, "$what: adoption removes it");
    }
};

subtest 'an archive file is extracted through the handle that its config was read from' => sub {
    my $dir = "$WORKDIR/dump";
    my $path = "$dir/vzdump-lxc-100-2026_01_01-00_00_00.tar.gz";
    my $make_archive = sub($target, $uid) {
        my $source = "$WORKDIR/archive-source";
        remove_tree($source);
        make_path("$source/etc/vzdump", $dir);
        file_set_contents("$source/etc/vzdump/pct.conf", backup_config("uid=$uid"));
        PVE::Tools::run_command(['tar', '-czf', $target, '-C', $source, './etc']);
    };
    $make_archive->($path, 'backupbackupbackupba');
    $make_archive->("$dir/other.tar.gz", 'anotheranotheranothe');

    # the path gets to name another archive once the file is open, before its config is read
    my $extract_config = PVE::Storage->can('extract_vzdump_config_tar');
    my $replace = {
        extract_vzdump_config_tar => sub {
            rename("$dir/other.tar.gz", $path) or die "rename failed - $!\n";
            return $extract_config->(@_);
        },
    };
    my $recover_config = $create_module->original('recover_config');
    my ($conf, undef, $opened) =
        with_mock($storage_module, $replace, sub { [$recover_config->($storage_cfg, $path, 200)] })
        ->@*;
    is($conf->{meta}, 'uid=backupbackupbackupba', 'config is read from the opened file');
    ok($opened->{fh}, 'the handle of the file is returned');

    my $rootdir = "$WORKDIR/rootfs/200";
    my $extract = sub($archive, $opened) {
        reset_state();
        remove_tree($rootdir);
        make_path($rootdir);
        return run_task(sub {
            $create_module->original('restore_archive')
                ->($storage_cfg, $archive, $rootdir, {}, 0, undef, $opened);
        });
    };
    my $extracted_uid = sub {
        my ($uid) = file_get_contents("$rootdir/etc/vzdump/pct.conf") =~ m/^meta: uid=(\S+)$/m;
        return $uid;
    };
    my $inherited = sub($fh) {
        return !($fh->fcntl(Fcntl::F_GETFD(), 0) & Fcntl::FD_CLOEXEC());
    };

    is($extract->($path, $opened), '', 'extraction succeeds') or diag($task_log);
    is($extracted_uid->(), 'backupbackupbackupba', 'data is extracted from the opened file');
    close($opened->{fh});

    $conf = $recover_config->($storage_cfg, $path, 200);
    is($conf->{meta}, 'uid=anotheranotheranothe', 'the path names another archive by now');

    # The restore can get the archive through another name. Until the extraction, a prune job can
    # remove the file and the name can get to point to an archive with another compression.
    my $link = "$dir/latest";
    symlink('vzdump-lxc-100-2026_01_01-00_00_00.tar.gz', $link) or die "symlink failed - $!\n";
    ($conf, undef, $opened) = $recover_config->($storage_cfg, $link, 200);
    unlink($link, $path) == 2 or die "unlink failed - $!\n";
    file_set_contents("$dir/newer.tar.xz", "not an archive\n");
    symlink('newer.tar.xz', $link) or die "symlink failed - $!\n";

    is($extract->($link, $opened), '', 'extraction succeeds after the file got removed')
        or diag($task_log);
    is($extracted_uid->(), 'anotheranotheranothe', 'data is extracted from the removed file');
    ok(!$inherited->($opened->{fh}), 'later child processes do not inherit the handle');

    my $tools_module = Test::MockModule->new('PVE::Tools');
    $tools_module->mock(run_command => sub { die "unable to start tar\n" });
    like(
        $extract->($link, $opened),
        qr/unable to start tar/,
        'extraction fails if tar does not start',
    );
    ok(!$inherited->($opened->{fh}), 'the handle is not inherited then either');
    $tools_module->unmock_all();
    close($opened->{fh});

    like(
        $extract->($path, undef),
        qr/^can't find file /,
        'without the handle, a removed file fails',
    );
};

subtest 'restore fails if the backup changed after its uid was read' => sub {
    # the merge of the config reads the backup again and finds another one
    my $mocked_restore_archive = PVE::LXC::Create->can('restore_archive');
    my $changes = {
        restore_archive => sub {
            $backup_raw_config =
                backup_config($BACKUP_META =~ s/uid=.*/uid=anotheranotheranothe/r);
            return $mocked_restore_archive->(@_);
        },
    };
    my $changed = "unable to restore CT 200 - backup changed during the restore: its uid"
        . " 'anotheranotheranothe' differs from uid 'backupbackupbackupba' read before";

    for my $archive ($BACKUP_VOLID, $PBS_VOLID) {
        my $name = $archive eq $PBS_VOLID ? 'backup server' : 'archive file';
        my $restore = sub($param = {}) {
            $backup_raw_config = backup_config($BACKUP_META);
            my $call = sub { restore_ct(200, { ostemplate => $archive, $param->%* }) };
            return with_mock($create_module, $changes, $call);
        };

        reset_state();
        like($restore->(), qr/^\Q$changed\E$/, "$name, unused VMID: restore fails");
        ok(!defined(read_raw_config(200)), "$name, unused VMID: nothing is left behind");

        # the checked backup has the uid of the container
        reset_state();
        write_raw_config(
            200,
            existing_config($EXISTING_META =~ s/uid=.*/uid=backupbackupbackupba/r),
        );
        like($restore->({ force => 1 }), qr/^\Q$changed\E$/, "$name, in place: restore fails");
        ok(
            !defined(read_raw_config(200)),
            "$name, in place: the other backup is not left behind with the uid of the container",
        );
    }
};

subtest 'restore over a container of another guest needs an override' => sub {
    my $existing_raw = existing_config($EXISTING_META);
    my $existing_conf = PVE::LXC::Config::parse_pct_config('/lxc/200.conf', $existing_raw);
    delete $existing_conf->{digest};

    my $setup = sub {
        reset_state();
        $backup_raw_config = backup_config($BACKUP_META);
        write_raw_config(200, $existing_raw);
    };
    my $refused = sub($name, $param, $expected_err) {
        $setup->();
        my $err = restore_ct(200, { force => 1, $param->%* });
        is($err, "unable to restore CT 200 - $expected_err\n", "$name: restore is refused");
        is($volumes_touched, 0, "$name: volumes are not touched");
        my $conf = PVE::LXC::Config->load_config(200);
        delete $conf->{digest};
        is_deeply($conf, $existing_conf, "$name: config is unchanged");
    };

    my $mismatch_err =
        "backup belongs to another guest: its uid 'backupbackupbackupba' differs from uid"
        . " 'existingexistingexis' of the existing CT 200 - use 'allow-identity-mismatch' to"
        . " overwrite the CT anyway";
    my $stdin_err =
        "cannot verify the guest identity of a backup from standard input before overwriting"
        . " CT 200 (uid 'existingexistingexis') - use 'allow-identity-mismatch' to overwrite the"
        . " CT anyway";
    my $ignored = "guest identity: ignoring backup uid backupbackupbackupba, CT 200 keeps uid"
        . " existingexistingexis";
    my $stdin = { ostemplate => '-', rootfs => 'local:4' };
    $refused->('different uid', {}, $mismatch_err);
    $refused->('different uid, unique', { unique => 1 }, $mismatch_err);
    $refused->('from STDIN', $stdin, $stdin_err);

    for my $param ({}, $stdin) {
        my $name = $param->{ostemplate} ? 'from STDIN' : 'from file';
        $setup->();
        my $err = restore_ct(200, { force => 1, 'allow-identity-mismatch' => 1, $param->%* });
        is($err, '', "$name: restore with override succeeds") or diag($task_log);
        is(
            PVE::LXC::Config->load_config(200)->{hostname},
            'backup',
            "$name: backup is restored",
        );
        is_deeply(
            identity_of(200),
            { uid => 'existingexistingexis', rtime => 1500000000000 },
            "$name: identity of the container is kept",
        );
        like($task_log, qr/^\Q$ignored\E$/m, "$name: override is logged");
        like(
            $task_log,
            qr/^guest identity: kept uid existingexistingexis$/m,
            "$name: result is logged",
        );
    }

    reset_state();
    $backup_raw_config = backup_config($BACKUP_META);
    write_raw_config(200, existing_config('ctime=1500000000'));
    my $err = restore_ct(200, { force => 1, $stdin->%* });
    is($err, '', 'restore from STDIN over a container without identity succeeds');
    is(identity_of(200)->{uid}, 'backupbackupbackupba', 'uid of the backup is adopted');

    $err = create_ct(201, { 'allow-identity-mismatch' => 1 });
    like($err, qr/allow-identity-mismatch/, 'override is only allowed for restores');

    my ($class, $method, undef, $fixed) = $PVE::CLI::pct::cmddef->{restore}->@*;
    is("$class->$method", 'PVE::API2::LXC->create_vm', 'pct restore uses the create API call');
    ok($fixed->{restore}, 'pct restore sets restore, so it accepts the override');
};

subtest 'restore over the container left behind by a restore of a backup' => sub {
    failed_restore_in_place();
    $backup_raw_config = backup_config($BACKUP_META =~ s/uid=.*/uid=anotheranotheranothe/r);
    my $err = restore_ct(200, { force => 1 });
    like(
        $err,
        qr/backup belongs to another guest: its uid .anotheranotheranothe. differs/,
        'another backup is refused',
    );
    is(pending_uid_of(200), 'backupbackupbackupba', 'pending uid is unchanged');

    $backup_raw_config = backup_config($BACKUP_META);
    my $param = { force => 1, ostemplate => '-', rootfs => 'local:4' };
    $err = restore_ct(200, $param);
    like(
        $err,
        qr/cannot verify the guest identity of a backup from standard input/,
        'the same backup from STDIN is refused',
    );

    $err = restore_ct(200, { $param->%*, 'allow-identity-mismatch' => 1 });
    is($err, '', 'from STDIN with override succeeds') or diag($task_log);
    is(
        identity_of(200)->{uid}, 'backupbackupbackupba', 'its uid is the pending uid: adopted',
    );
    is(pending_uid_of(200), undef, 'pending uid is removed');
};

subtest 'remote migration adopts the guest identity of the source' => sub {
    my $source_meta = 'ctime=1600000000,rtime=1600000000000,uid=sourcesourcesourceso';
    my $incoming = $INCOMING_CONFIG =~ s/^meta: .*$/meta: $source_meta/mr;
    # like the source sends it
    my $identity_cmd =
        { cmd => 'identity', uid => 'sourcesourcesourceso', 'allow-new-uid' => 0 };
    my $config_cmd = { cmd => 'config', conf => $incoming };
    my $quit_cmd = { cmd => 'quit', cleanup => 0 };
    my $cleanup_cmd = { cmd => 'quit', cleanup => 1 };
    $now_ms = 1_700_000_000_000;

    my $migrate = sub {
        my ($name, $setup, $allow_new_uid, $expected_result, $expected_uid) = @_;

        reset_configs();
        $setup->();
        my ($err, $replies) = run_mtunnel(
            300,
            { $identity_cmd->%*, 'allow-new-uid' => $allow_new_uid },
            $config_cmd,
            $quit_cmd,
        );
        is($err, '', "$name: tunnel exits normally") or diag(explain($replies), $task_log);
        ok($replies->[0]->{success}, "$name: identity command succeeds");
        ok($replies->[1]->{success}, "$name: config command succeeds");
        ok(!exists($replies->[1]->{identity}), "$name: config command adopts nothing");

        my $identity = $replies->[0]->{identity};
        is($identity->{result}, $expected_result, "$name: result is returned");
        my $stored = identity_of(300);
        is($identity->{uid}, $stored->{uid}, "$name: returned uid is the stored one");
        if (defined($expected_uid)) {
            is($stored->{uid}, $expected_uid, "$name: uid");
        } else {
            isnt(
                $stored->{uid},
                'sourcesourcesourceso',
                "$name: uid is not the one of the source",
            );
        }
        is($stored->{rtime}, $now_ms, "$name: rtime is the time of the migration");
        is(meta_of(300)->{ctime}, 1600000000, "$name: ctime of the source is kept");
        like(
            $task_log,
            qr/^guest identity: .*$identity->{uid}/m,
            "$name: result is logged on the target",
        );

        return $identity;
    };

    $migrate->('free uid', sub { }, 0, 'adopted', 'sourcesourcesourceso');
    my $reserved_write = $written->{300}->[1];
    ok(
        $reserved_write =~ m/^lock: create$/m
            && $reserved_write =~ m/^meta: .*uid=sourcesourcesourceso$/m,
        'free uid: adopted right after the reservation',
    );

    my $in_use_by_ct =
        sub { write_raw_config(150, existing_config('uid=sourcesourcesourceso')) };
    my $in_use_by_vm =
        sub { write_raw_vm_config(151, "memory: 512\nmeta: uid=sourcesourcesourceso\n") };
    $migrate->('uid used by another container, allow-new-uid', $in_use_by_ct, 1, 'in-use');
    $migrate->('uid used by a VM, allow-new-uid', $in_use_by_vm, 1, 'in-use');

    for my $case (
        ['uid used by another container', $in_use_by_ct, 150],
        ['uid used by a VM', $in_use_by_vm, 151],
    ) {
        my ($name, $setup, $holder) = $case->@*;
        reset_configs();
        $setup->();
        my ($err, $replies) = run_mtunnel(300, $identity_cmd, $cleanup_cmd);
        is($err, '', "$name: tunnel exits normally") or diag($task_log);
        ok(!$replies->[0]->{success}, "$name: identity command fails");
        is(
            $replies->[0]->{msg},
            "failed to handle 'identity' command - guest $holder in the target cluster already"
                . " has the uid 'sourcesourcesourceso' of this guest - use 'allow-new-uid' to"
                . " migrate it with a new uid\n",
            "$name: migration is refused",
        );
        is(scalar($written->{300}->@*), 1, "$name: nothing written besides the reservation");
        ok($replies->[1]->{success}, "$name: cleanup succeeds");
        ok(!defined(read_raw_config(300)), "$name: reservation is removed");
    }

    for my $case (
        ['source without identity command', $incoming],
        ['source without identity command and uid', $INCOMING_CONFIG],
    ) {
        my ($name, $conf) = $case->@*;
        reset_configs();
        my ($err, $replies) = run_mtunnel(300, { cmd => 'config', conf => $conf }, $quit_cmd);
        is($err, '', "$name: tunnel exits normally") or diag($task_log);
        ok($replies->[0]->{success}, "$name: config command succeeds");
        my $uid = identity_of(300)->{uid};
        like($uid, qr/^[a-z2-7]{20}$/, "$name: container has a uid");
        isnt($uid, 'sourcesourcesourceso', "$name: it is a new one");
        like(
            $task_log,
            qr/^guest identity: the source sent no uid, .* has the new uid $uid$/m,
            "$name: target task logs the new uid",
        );
        like(
            $task_log,
            qr/^guest identity: .* a migration back there gets refused$/m,
            "$name: and that the container cannot migrate back",
        );
    }

    my $real_adopt = \&PVE::GuestIdentity::adopt;
    my ($lock, $locked);
    $identity_module->mock(
        adopt => sub {
            my ($class, $vmid) = @_;
            $lock = PVE::LXC::Config->load_config($vmid)->{lock};
            open(my $fh, '>>', "$WORKDIR/lock/pve-config-$vmid.lock")
                or die "open failed - $!\n";
            $locked = !flock($fh, LOCK_EX | LOCK_NB);
            close($fh);
            return $real_adopt->(@_);
        },
    );
    $migrate->('order of the writes', sub { }, 0, 'adopted', 'sourcesourcesourceso');
    $identity_module->unmock('adopt');
    is($lock, 'create', 'identity is adopted before the config of the source is written');
    ok($locked, 'config lock is held while adopting the identity');

    reset_configs();
    $domain_lock_error = "cfs-lock 'domain-guest-identity' error: got lock request timeout\n";
    my ($err, $replies) = run_mtunnel(300, $identity_cmd, $cleanup_cmd);
    $domain_lock_error = undef;
    is($err, '', 'identity lock failure: tunnel exits normally') or diag($task_log);
    ok(!$replies->[0]->{success}, 'identity lock failure: identity command fails');
    is(
        $replies->[0]->{msg},
        "failed to handle 'identity' command - unable to adopt the uid of the source guest -"
            . " cfs-lock 'domain-guest-identity' error: got lock request timeout\n",
        'identity lock failure: error is returned',
    );
    ok($replies->[1]->{success}, 'identity lock failure: cleanup succeeds');
    ok(!defined(read_raw_config(300)), 'identity lock failure: target config is removed');

    reset_configs();
    ($err, $replies) =
        run_mtunnel(300, $identity_cmd, $identity_cmd, $config_cmd, $identity_cmd, $quit_cmd);
    is($err, '', 'repeated identity: tunnel exits normally');
    ok($replies->[0]->{success}, 'first identity command succeeds');
    ok($replies->[2]->{success}, 'config command succeeds');
    unlike($task_log, qr/the source sent no uid/, 'no note about a source without uid');
    for my $i (1, 3) {
        like(
            $replies->[$i]->{msg},
            qr/the uid can only be adopted once, before the config arrives/,
            "identity command at position $i fails",
        );
    }

    reset_configs();
    my $broken = $incoming =~ s/^rootfs: local:/rootfs: iso:/mr;
    ($err, $replies) = run_mtunnel(
        300,
        $identity_cmd,
        { cmd => 'config', conf => $broken },
        $config_cmd,
        $config_cmd,
        $quit_cmd,
    );
    is($err, '', 'repeated config: tunnel exits normally');
    is($replies->[0]->{identity}->{result}, 'adopted', 'uid is adopted at the start');
    ok(!$replies->[1]->{success}, 'failing config command fails');
    ok($replies->[2]->{success}, 'retry of the config command succeeds');
    ok(!$replies->[3]->{success}, 'config command after success fails');
    is_deeply(
        identity_of(300),
        { uid => 'sourcesourcesourceso', rtime => $now_ms },
        'identity adopted at the start is kept',
    );
};

subtest 'remote migration sends the guest identity on the source' => sub {
    my $source_raw = <<~'EOF';
        arch: amd64
        hostname: source
        memory: 512
        meta: ctime=1600000000,rtime=1600000000000,uid=sourcesourcesourceso
        ostype: debian
        unprivileged: 1
        EOF
    reset_configs();
    write_raw_config(987, $source_raw);

    my $log = '';
    my $migrate_module = Test::MockModule->new('PVE::AbstractMigrate');
    $migrate_module->mock(log => sub { $log .= "$_[1]: $_[2]\n" });

    my ($commands, $reply) = ([]);
    my $tunnel_module = Test::MockModule->new('PVE::Tunnel');
    $tunnel_module->mock(
        write_tunnel => sub {
            my ($tunnel, $timeout, $command, $params) = @_;
            push $commands->@*, { command => $command, timeout => $timeout, params => $params };
            return $reply;
        },
    );

    my $new_migration = sub($opts = {}) {
        return bless {
            opts => { remote => { vmid => 300 }, $opts->%* },
            vmid => 987,
            node => 'remote-node',
            nodeip => '192.0.2.1',
            storecfg => $storage_cfg,
            vmconf => PVE::LXC::Config->load_config(987),
            tunnel => {},
            },
            'PVE::LXC::Migrate';
    };
    my $adopt_on_target = sub($self) {
        ($commands, $log) = ([], '');
        return run_task(sub { $self->adopt_identity_on_target('PVE::LXC::Config', {}) });
    };

    $reply = {
        success => 1,
        identity => {
            result => 'adopted',
            uid => 'sourcesourcesourceso',
            requested => 'sourcesourcesourceso',
        },
    };
    is($adopt_on_target->($new_migration->()), '', 'identity command succeeds');
    is_deeply(
        $commands,
        [{
            command => 'identity',
            timeout => 60,
            params => { uid => 'sourcesourcesourceso', 'allow-new-uid' => 0 },
        }],
        'uid is sent, the source waits for the identity lock of the target',
    );
    my $adopted = 'guest identity: the migrated guest keeps uid sourcesourcesourceso';
    like($log, qr/^info: \Q$adopted\E$/m, 'result of the target is logged');

    is($adopt_on_target->($new_migration->({ 'allow-new-uid' => 1 })), '', 'allow-new-uid');
    is($commands->[0]->{params}->{'allow-new-uid'}, 1, 'allow-new-uid is sent');

    # a target with a newer version has accepted the uid at this point
    $reply =
        { success => 1, identity => { result => 'future', uid => 'sourcesourcesourceso' } };
    is($adopt_on_target->($new_migration->()), '', 'outcome unknown here does not fail');
    like(
        $log,
        qr/^warn: guest identity: unknown result 'future' of the target$/m,
        'unknown outcome is a warning',
    );

    write_raw_config(987, $source_raw =~ s/^meta: .*\n//mr);
    $reply = { success => 1 };
    is($adopt_on_target->($new_migration->()), '', 'source without uid');
    my $uid = identity_of(987)->{uid};
    like($uid, qr/^[a-z2-7]{20}$/, 'source without uid: it gets a uid first');
    is_deeply(
        $commands,
        [{
            command => 'identity',
            timeout => 60,
            params => { uid => $uid, 'allow-new-uid' => 0 },
        }],
        'source without uid: that uid is sent',
    );
    write_raw_config(987, $source_raw);

    $reply = { success => 1 };
    ($commands, $log) = ([], '');
    is(run_task(sub { $new_migration->()->phase1(987) }), '', 'phase 1 succeeds')
        or diag($log, $task_log);
    is($commands->[0]->{command}, 'config', 'phase 1 sends the config');
    like(
        $commands->[0]->{params}->{conf},
        qr/^meta: .*uid=sourcesourcesourceso/m,
        'config is sent with the identity',
    );
    is($commands->[0]->{timeout}, 10, 'config command does not wait for the identity lock');
    unlike($log, qr/guest identity/, 'nothing is logged about the identity');
    is(identity_of(987)->{uid}, 'sourcesourcesourceso', 'source keeps its uid');
    PVE::LXC::Config->remove_lock(987, 'migrate');
};

subtest 'remote migration keeps the source if the target refuses the identity' => sub {
    reset_configs();
    write_raw_config(987, <<~'EOF');
        arch: amd64
        hostname: source
        memory: 512
        meta: ctime=1600000000,rtime=1600000000000,uid=sourcesourcesourceso
        ostype: debian
        unprivileged: 1
        EOF

    my $log = '';
    my $migrate_module = Test::MockModule->new('PVE::AbstractMigrate');
    $migrate_module->mock(log => sub { $log .= "$_[1]: $_[2]\n" });

    my ($commands, $cleanup) = ([]);
    my $tunnel_module = Test::MockModule->new('PVE::Tunnel');
    $tunnel_module->mock(
        fork_websocket_tunnel => sub { return { version => 3, age => 1 } },
        write_tunnel => sub {
            my ($tunnel, $timeout, $command) = @_;
            push $commands->@*, $command;
            die "error - tunnel command '$command' failed - failed to handle 'identity' command"
                . " - guest 150 in the target cluster already has the uid 'sourcesourcesourceso'"
                . " of this guest - use 'allow-new-uid' to migrate it with a new uid\n";
        },
        finish_tunnel => sub { (undef, $cleanup) = @_ },
    );

    my ($running, $stopped, $destroyed) = (1, 0, 0);
    my $destroy_ct = \&PVE::LXC::destroy_lxc_container;
    $lxc_module->mock(
        check_running => sub { return $running },
        vm_stop => sub { $stopped = 1 },
        destroy_lxc_container => sub { $destroyed = 1 },
    );

    my $err = run_task(sub {
        PVE::LXC::Migrate->migrate(
            'remote-node',
            '192.0.2.1',
            987,
            {
                remote => { vmid => 300, conn => { host => '192.0.2.1', port => 8006 } },
                restart => 1,
                delete => 1,
            },
        );
    });

    $lxc_module->mock(check_running => sub { return 0 }, destroy_lxc_container => $destroy_ct);
    $lxc_module->unmock('vm_stop');

    like($err, qr/migration aborted/, 'migration fails');
    like($log, qr/^err: .*already has the uid 'sourcesourcesourceso'/m, 'refusal is logged');
    is_deeply($commands, ['identity'], 'nothing else is sent to the target');
    is($cleanup, 1, 'target gets cleaned up');
    ok(!$stopped, 'source is not stopped for the restart migration');
    ok(!$destroyed, 'source is not destroyed');
    my $conf = PVE::LXC::Config->load_config(987);
    ok(!defined($conf->{lock}), 'source is not locked');
    is(identity_of(987)->{uid}, 'sourcesourcesourceso', 'source keeps its uid');
};

remove_tree($WORKDIR);

done_testing();
