package PVE::API2::LXC;

use strict;
use warnings;

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param run_command);
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::RRD;
use PVE::DataCenterConfig;
use PVE::AccessControl;
use PVE::Firewall;
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::ReplicationConfig;
use PVE::RS::OCI;
use PVE::LXC;
use PVE::LXC::Create;
use PVE::LXC::Migrate;
use PVE::LXC::Namespaces;
use PVE::GuestHelpers;
use PVE::VZDump::Plugin;
use PVE::API2::LXC::Config;
use PVE::API2::LXC::Status;
use PVE::API2::LXC::Snapshot;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SSHInfo;
use base qw(PVE::RESTHandler);

BEGIN {
    if (!$ENV{PVE_GENERATING_DOCS}) {
        require PVE::HA::Env::PVE2;
        import PVE::HA::Env::PVE2;
        require PVE::HA::Config;
        import PVE::HA::Config;
    }
}

my sub assert_not_restore_from_external {
    my ($archive, $storage_cfg) = @_;

    my ($storeid, undef) = PVE::Storage::parse_volume_id($archive, 1);

    return if !defined($storeid);
    return if !PVE::Storage::storage_has_feature($storage_cfg, $storeid, 'backup-provider');

    die "refusing to restore privileged container backup from external source\n";
}

my $check_storage_access_migrate = sub {
    my ($rpcenv, $authuser, $storecfg, $storage, $node) = @_;

    PVE::Storage::storage_check_enabled($storecfg, $storage, $node);

    $rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace']);

    my $scfg = PVE::Storage::storage_config($storecfg, $storage);
    die "storage '$storage' does not support CT rootdirs\n"
        if !$scfg->{content}->{rootdir};
};

__PACKAGE__->register_method({
    subclass => "PVE::API2::LXC::Config",
    path => '{vmid}/config',
});

__PACKAGE__->register_method({
    subclass => "PVE::API2::LXC::Status",
    path => '{vmid}/status',
});

__PACKAGE__->register_method({
    subclass => "PVE::API2::LXC::Snapshot",
    path => '{vmid}/snapshot',
});

__PACKAGE__->register_method({
    subclass => "PVE::API2::Firewall::CT",
    path => '{vmid}/firewall',
});

__PACKAGE__->register_method({
    name => 'vmlist',
    path => '',
    method => 'GET',
    description => "LXC container index (per node).",
    permissions => {
        description => "Only list CTs where you have VM.Audit permission on /vms/<vmid>.",
        user => 'all',
    },
    proxyto => 'node',
    protected => 1, # /proc files are only readable by root
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
        },
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => $PVE::LXC::vmstatus_return_properties,
        },
        links => [{ rel => 'child', href => "{vmid}" }],
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $vmstatus = PVE::LXC::vmstatus();

        my $res = [];
        foreach my $vmid (keys %$vmstatus) {
            next if !$rpcenv->check($authuser, "/vms/$vmid", ['VM.Audit'], 1);

            my $data = $vmstatus->{$vmid};
            push @$res, $data;
        }

        return $res;

    },
});

__PACKAGE__->register_method({
    name => 'create_vm',
    path => '',
    method => 'POST',
    description => "Create or restore a container.",
    permissions => {
        user => 'all', # check inside
        description =>
            "You need 'VM.Allocate' permission on /vms/{vmid} or on the VM pool /pool/{pool}. "
            . "For restore, it is enough if the user has 'VM.Backup' permission and the VM already exists. "
            . "You also need 'Datastore.AllocateSpace' permissions on the storage. "
            . "For privileged containers, 'Sys.Modify' permissions on '/' are required.",
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => PVE::LXC::Config->json_config_properties({
            node => get_standard_option('pve-node'),
            vmid => get_standard_option(
                'pve-vmid',
                { completion => \&PVE::Cluster::complete_next_vmid },
            ),
            ostemplate => {
                description => "The OS template or backup file.",
                type => 'string',
                maxLength => 255,
                completion => \&PVE::LXC::complete_os_templates,
            },
            password => {
                optional => 1,
                type => 'string',
                description => "Sets root password inside container.",
                minLength => 5,
            },
            storage => get_standard_option(
                'pve-storage-id',
                {
                    description => "Default Storage.",
                    completion => \&PVE::LXC::complete_storage,
                    default => 'local',
                    optional => 1,
                },
            ),
            force => {
                optional => 1,
                type => 'boolean',
                description => "Allow to overwrite existing container.",
            },
            restore => {
                optional => 1,
                type => 'boolean',
                description => "Mark this as restore task.",
            },
            unique => {
                optional => 1,
                type => 'boolean',
                description => "Assign a unique random ethernet address.",
                requires => 'restore',
            },
            pool => {
                optional => 1,
                type => 'string',
                format => 'pve-poolid',
                description => "Add the VM to the specified pool.",
            },
            'ignore-unpack-errors' => {
                optional => 1,
                type => 'boolean',
                description => "Ignore errors when extracting the template.",
            },
            'ssh-public-keys' => {
                optional => 1,
                type => 'string',
                description => "Setup public SSH keys (one key per line, " . "OpenSSH format).",
            },
            bwlimit => {
                description => "Override I/O bandwidth limit (in KiB/s).",
                optional => 1,
                type => 'number',
                minimum => '0',
                default => 'restore limit from datacenter or storage config',
            },
            start => {
                optional => 1,
                type => 'boolean',
                default => 0,
                description => "Start the CT after its creation finished successfully.",
            },
            'ha-managed' => {
                optional => 1,
                type => 'boolean',
                default => 0,
                description => "Add the CT as a HA resource after it was created.",
            },
        }),
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        PVE::Cluster::check_cfs_quorum();

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');
        my $vmid = extract_param($param, 'vmid');
        my $ignore_unpack_errors = extract_param($param, 'ignore-unpack-errors');
        my $bwlimit = extract_param($param, 'bwlimit');
        my $start_after_create = extract_param($param, 'start');
        my $ha_managed = extract_param($param, 'ha-managed');

        my $basecfg_fn = PVE::LXC::Config->config_file($vmid);
        my $same_container_exists = -f $basecfg_fn;

        # 'unprivileged' is read-only, so we can't pass it to update_pct_config
        my $unprivileged = extract_param($param, 'unprivileged');
        my $restore = extract_param($param, 'restore');
        my $unique = extract_param($param, 'unique');

        $param->{cpuunits} = PVE::CGroup::clamp_cpu_shares($param->{cpuunits})
            if defined($param->{cpuunits}); # clamp value depending on cgroup version

        # used to skip firewall config restore if user lacks permission
        my $skip_fw_config_restore = 0;

        if ($restore) {
            # fixme: limit allowed parameters
        } else {
            $unprivileged = 1 if !defined($unprivileged);
            $rpcenv->check($authuser, '/', ['Sys.Modify']) if !$unprivileged;
        }

        my $force = extract_param($param, 'force');

        if (!($same_container_exists && $restore && $force)) {
            PVE::Cluster::check_vmid_unused($vmid);
        } else {
            die "can't overwrite running container\n" if PVE::LXC::check_running($vmid);
            my $conf = PVE::LXC::Config->load_config($vmid);
            PVE::LXC::Config->check_protection($conf, "unable to restore CT $vmid");
        }

        my $password = extract_param($param, 'password');
        my $ssh_keys = extract_param($param, 'ssh-public-keys');
        PVE::Tools::validate_ssh_public_keys($ssh_keys) if defined($ssh_keys);

        my $pool = extract_param($param, 'pool');
        $rpcenv->check_pool_exist($pool) if defined($pool);

        if ($rpcenv->check($authuser, "/vms/$vmid", ['VM.Allocate'], 1)) {
            # OK
        } elsif ($pool && $rpcenv->check($authuser, "/pool/$pool", ['VM.Allocate'], 1)) {
            # OK
        } elsif (
            $restore
            && $force
            && $same_container_exists
            && $rpcenv->check($authuser, "/vms/$vmid", ['VM.Backup'], 1)
        ) {
            # OK: user has VM.Backup permissions, and want to restore an existing VM

            # we don't want to restore a container-provided FW conf in this case
            # since the user is lacking permission to configure the container's FW
            $skip_fw_config_restore = 1;

            # error out if a user tries to change from unprivileged to privileged without required privileges
            # explicit change is checked here, implicit is checked down below or happening in root-only paths
            my $conf = PVE::LXC::Config->load_config($vmid);
            if ($conf->{unprivileged} && defined($unprivileged) && !$unprivileged) {
                $rpcenv->check($authuser, '/', ['Sys.Modify']);
            }
        } else {
            raise_perm_exc();
        }

        my $ostemplate = extract_param($param, 'ostemplate');
        my $storage = extract_param($param, 'storage') // 'local';

        PVE::LXC::check_ct_modify_config_perm(
            $rpcenv, $authuser, $vmid, $pool, undef, $param, [], $unprivileged,
        );

        my $storage_cfg = cfs_read_file("storage.cfg");

        my $archive;
        if ($ostemplate eq '-') {
            die "pipe requires cli environment\n"
                if $rpcenv->{type} ne 'cli';
            die "pipe can only be used with restore tasks\n"
                if !$restore;
            $archive = '-';
            die "restore from pipe requires rootfs parameter\n" if !defined($param->{rootfs});
        } else {
            my $content_type = $restore ? 'backup' : 'vztmpl';
            PVE::Storage::check_volume_access(
                $rpcenv, $authuser, $storage_cfg, $vmid, $ostemplate, $content_type,
            );
            $archive = $ostemplate;
        }

        my %used_storages;
        my $check_and_activate_storage = sub {
            my ($sid) = @_;

            my $scfg = PVE::Storage::storage_check_enabled($storage_cfg, $sid, $node);

            raise_param_exc({
                storage => "storage '$sid' does not support container directories" })
                if !$scfg->{content}->{rootdir};

            $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

            PVE::Storage::activate_storage($storage_cfg, $sid);
            $used_storages{$sid} = 1;
        };

        my $conf = {};

        my $is_root = $authuser eq 'root@pam';

        my $no_disk_param = {};
        my $mp_param = {};
        my $storage_only_mode = 1;
        foreach my $opt (keys %$param) {
            my $value = $param->{$opt};
            if ($opt eq 'rootfs' || $opt =~ m/^mp\d+$/) {
                # allow to use simple numbers (add default storage in that case)
                if ($value =~ m/^\d+(\.\d+)?$/) {
                    $mp_param->{$opt} = "$storage:$value";
                } else {
                    $mp_param->{$opt} = $value;
                }
                $storage_only_mode = 0;
            } elsif ($opt =~ m/^unused\d+$/) {
                warn "ignoring '$opt', cannot create/restore with unused volume\n";
                delete $param->{$opt};
            } else {
                $no_disk_param->{$opt} = $value;
            }
        }

        die "mount points configured, but 'rootfs' not set - aborting\n"
            if !$storage_only_mode && !defined($mp_param->{rootfs});

        # check storage access, activate storage
        my $delayed_mp_param = {};
        PVE::LXC::Config->foreach_volume(
            $mp_param,
            sub {
                my ($ms, $mountpoint) = @_;

                my $volid = $mountpoint->{volume};
                my $mp = $mountpoint->{mp};

                if ($mountpoint->{type} ne 'volume') { # bind or device
                    die "Only root can pass arbitrary filesystem paths.\n"
                        if !$is_root;
                } else {
                    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
                    &$check_and_activate_storage($sid);
                }
            },
        );

        # check/activate default storage
        &$check_and_activate_storage($storage) if !defined($mp_param->{rootfs});

        PVE::LXC::Config->update_pct_config($vmid, $conf, 0, $no_disk_param);

        $conf->{unprivileged} = 1 if $unprivileged;

        my $emsg = $restore ? "unable to restore CT $vmid -" : "unable to create CT $vmid -";

        eval { PVE::LXC::Config->create_and_lock_config($vmid, $force) };
        die "$emsg $@" if $@;

        my $destroy_config_on_error = !$same_container_exists;

        my $code = sub {
            my $old_conf = PVE::LXC::Config->load_config($vmid);
            my $was_template;

            my $vollist = [];
            eval {
                my $orig_mp_param; # only used if $restore
                if ($restore) {
                    die "can't overwrite running container\n" if PVE::LXC::check_running($vmid);
                    if ($archive ne '-') {
                        my $orig_conf;
                        print "recovering backed-up configuration from '$archive'\n";
                        ($orig_conf, $orig_mp_param) =
                            PVE::LXC::Create::recover_config($storage_cfg, $archive, $vmid);

                        for my $opt (keys %$orig_conf) {
                            # early check before disks are created
                            # the "real" check is in later on when actually merging the configs
                            if ($opt =~ /^net\d+$/ && !defined($param->{$opt})) {
                                PVE::LXC::check_bridge_access(
                                    $rpcenv, $authuser, $orig_conf->{$opt},
                                );
                            }
                        }

                        $was_template = delete $orig_conf->{template};

                        # When we're root call 'restore_configuration' with restricted=0,
                        # causing it to restore the raw lxc entries, among which there may be
                        # 'lxc.idmap' entries. We need to make sure that the extracted contents
                        # of the container match up with the restored configuration afterwards:
                        $conf->{lxc} = $orig_conf->{lxc} if $is_root;

                        $conf->{unprivileged} = $orig_conf->{unprivileged}
                            if !defined($unprivileged) && defined($orig_conf->{unprivileged});

                        assert_not_restore_from_external($archive, $storage_cfg)
                            if !$conf->{unprivileged};

                        # implicit privileged change, or creating a new privileged container is checked here
                        if (
                            (!$same_container_exists || $old_conf->{unprivileged})
                            && !$conf->{unprivileged}
                        ) {
                            $rpcenv->check($authuser, '/', ['Sys.Modify']);
                        }
                    }
                }
                if ($storage_only_mode) {
                    if ($restore) {
                        if (!defined($orig_mp_param)) {
                            print "recovering backed-up configuration from '$archive'\n";
                            (undef, $orig_mp_param) =
                                PVE::LXC::Create::recover_config($storage_cfg, $archive, $vmid);
                        }
                        $mp_param = $orig_mp_param;
                        die
                            "rootfs configuration could not be recovered, please check and specify manually!\n"
                            if !defined($mp_param->{rootfs});
                        PVE::LXC::Config->foreach_volume(
                            $mp_param,
                            sub {
                                my ($ms, $mountpoint) = @_;
                                my $type = $mountpoint->{type};
                                if ($type eq 'volume') {
                                    die
                                        "unable to detect disk size - please specify $ms (size)\n"
                                        if !defined($mountpoint->{size});
                                    my $disksize = $mountpoint->{size} / (1024 * 1024 * 1024); # create_disks expects GB as unit size
                                    delete $mountpoint->{size};
                                    $mountpoint->{volume} = "$storage:$disksize";
                                    $mp_param->{$ms} = PVE::LXC::Config->print_ct_mountpoint(
                                        $mountpoint,
                                        $ms eq 'rootfs',
                                    );
                                } else {
                                    my $type = $mountpoint->{type};
                                    die
                                        "restoring rootfs to $type mount is only possible by specifying -rootfs manually!\n"
                                        if ($ms eq 'rootfs');
                                    die
                                        "restoring '$ms' to $type mount is only possible for root\n"
                                        if !$is_root;

                                    if ($mountpoint->{backup}) {
                                        warn "WARNING - unsupported configuration!\n";
                                        warn
                                            "backup was enabled for $type mount point $ms ('$mountpoint->{mp}')\n";
                                        warn
                                            "mount point configuration will be restored after archive extraction!\n";
                                        warn
                                            "contained files will be restored to wrong directory!\n";
                                    }
                                    delete $mp_param->{$ms}; # actually delay bind/dev mps
                                    $delayed_mp_param->{$ms} =
                                        PVE::LXC::Config->print_ct_mountpoint(
                                            $mountpoint,
                                            $ms eq 'rootfs',
                                        );
                                }
                            },
                        );
                    } else {
                        $mp_param->{rootfs} = "$storage:4"; # defaults to 4GB
                    }
                }

                # up until here we did not modify the container, besides the lock
                $destroy_config_on_error = 1;

                $vollist = PVE::LXC::create_disks($storage_cfg, $vmid, $mp_param, $conf);

                # we always have the 'create' lock so check for more than 1 entry
                if (scalar(keys %$old_conf) > 1) {
                    # destroy old container volumes
                    PVE::LXC::destroy_lxc_container(
                        $storage_cfg,
                        $vmid,
                        $old_conf,
                        { lock => 'create' },
                    );
                }

                eval {
                    my $rootdir = PVE::LXC::mount_all($vmid, $storage_cfg, $conf, 1);
                    my $archivepath = '-';
                    $archivepath = PVE::Storage::abs_filesystem_path($storage_cfg, $archive)
                        if ($archive ne '-');
                    $bwlimit = PVE::Storage::get_bandwidth_limit(
                        'restore', [keys %used_storages], $bwlimit,
                    );
                    my $is_oci = 0;

                    if ($restore && $archive ne '-') {
                        print "restoring '$archive' now..\n";
                    } elsif ($archivepath =~ /\.tar$/) {
                        # Check whether archive is an OCI image
                        my ($has_oci_layout, $has_index_json, $has_blobs) = (0, 0, 0);
                        PVE::Tools::run_command(
                            ['tar', '-tf', $archivepath],
                            outfunc => sub {
                                my $line = shift;
                                $has_oci_layout = 1 if $line eq 'oci-layout';
                                $has_index_json = 1 if $line eq 'index.json';
                                $has_blobs = 1 if $line =~ /^blobs\//m;
                            },
                        );

                        $is_oci = 1 if $has_oci_layout && $has_index_json && $has_blobs;
                    }

                    if ($is_oci) {
                        # Extract the OCI image
                        my ($id_map, undef, undef) = PVE::LXC::parse_id_maps($conf);
                        my $oci_config = PVE::LXC::Namespaces::run_in_userns(
                            sub {
                                PVE::RS::OCI::parse_and_extract_image($archivepath, $rootdir);
                            },
                            $id_map,
                        );

                        # Set the entrypoint and arguments if specified by the OCI image
                        my @init_cmd = ();
                        push(@init_cmd, @{ $oci_config->{Entrypoint} })
                            if $oci_config->{Entrypoint};
                        push(@init_cmd, @{ $oci_config->{Cmd} }) if $oci_config->{Cmd};
                        if (@init_cmd) {
                            my $init_cmd_str = shift(@init_cmd);
                            if (@init_cmd) {
                                $init_cmd_str .= ' ';
                                $init_cmd_str .= join(
                                    ' ',
                                    map {
                                        my $s = $_;
                                        $s =~ s/"/\\"/g;
                                        qq{"$_"}
                                    } @init_cmd,
                                );
                            }
                            if ($init_cmd_str ne '/sbin/init') {
                                push @{ $conf->{lxc} }, ['lxc.init.cmd', $init_cmd_str];

                                # An entrypoint other than /sbin/init breaks the tty console mode.
                                # This is fixed by setting cmode: console
                                $conf->{cmode} = 'console';
                            }
                        }

                        push @{ $conf->{lxc} }, ['lxc.init.cwd', $oci_config->{WorkingDir}]
                            if ($oci_config->{WorkingDir});

                        if (my $envs = $oci_config->{Env}) {
                            for my $env (@{$envs}) {
                                push @{ $conf->{lxc} }, ['lxc.environment.runtime', $env];
                            }
                        }

                        my $stop_signal = $oci_config->{StopSignal} // "SIGTERM";
                        push @{ $conf->{lxc} }, ['lxc.signal.halt', $stop_signal];
                    } else {
                        # Not an OCI image, so restore it as an LXC image instead
                        PVE::LXC::Create::restore_archive(
                            $storage_cfg,
                            $archive,
                            $rootdir,
                            $conf,
                            $ignore_unpack_errors,
                            $bwlimit,
                        );
                    }

                    if ($restore) {
                        print "merging backed-up and given configuration..\n";
                        PVE::LXC::Create::restore_configuration(
                            $vmid,
                            $storage_cfg,
                            $archive,
                            $rootdir,
                            $conf,
                            !$is_root,
                            $unique,
                            $skip_fw_config_restore,
                        );
                        PVE::LXC::create_ifaces_ipams_ips($conf, $vmid) if $unique;
                        my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir);
                        $lxc_setup->template_fixup($conf);
                    } else {
                        my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir); # detect OS
                        PVE::LXC::Config->write_config($vmid, $conf); # safe config (after OS detection)
                        $lxc_setup->post_create_hook($password, $ssh_keys);
                    }
                };
                my $err = $@;
                PVE::LXC::umount_all($vmid, $storage_cfg, $conf, $err ? 1 : 0);
                PVE::Storage::deactivate_volumes(
                    $storage_cfg,
                    PVE::LXC::Config->get_vm_volumes($conf),
                );
                die $err if $err;
                # set some defaults
                $conf->{hostname} ||= "CT$vmid";
                $conf->{memory} ||= 512;
                $conf->{swap} //= 512;
                foreach my $mp (keys %$delayed_mp_param) {
                    $conf->{$mp} = $delayed_mp_param->{$mp};
                }
                # If the template flag was set, we try to convert again to template after restore
                if ($was_template) {
                    print STDERR "Convert restored container to template...\n";
                    PVE::LXC::template_create($vmid, $conf);
                    $conf->{template} = 1;
                }
                PVE::LXC::Config->write_config($vmid, $conf);
            };
            if (my $err = $@) {
                eval { PVE::LXC::delete_ifaces_ipams_ips($conf, $vmid) };
                warn $@ if $@;
                PVE::LXC::destroy_disks($storage_cfg, $vollist);
                if ($destroy_config_on_error) {
                    eval { PVE::LXC::Config->destroy_config($vmid) };
                    warn $@ if $@;

                    if (!$skip_fw_config_restore) { # Only if user has permission to change the fw
                        PVE::Firewall::remove_vmfw_conf($vmid);
                        warn $@ if $@;
                    }
                }
                die "$emsg $err";
            }
            PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
        };

        my $workername = $restore ? 'vzrestore' : 'vzcreate';
        my $realcmd = sub {
            eval { PVE::LXC::Config->lock_config($vmid, $code); };
            if (my $err = $@) {
                # if we aborted before changing the container, we must remove the create lock
                if (!$destroy_config_on_error) {
                    PVE::LXC::Config->remove_lock($vmid, 'create');
                }
                die $err;
            } elsif ($start_after_create) {
                PVE::API2::LXC::Status->vm_start({ vmid => $vmid, node => $node });
            }

            if ($ha_managed) {
                print "Add as HA resource\n";
                my $state = $start_after_create ? 'started' : 'stopped';
                eval {
                    PVE::API2::HA::Resources->create({ sid => "ct:$vmid", state => $state });
                };
                warn $@ if $@;
            }
        };

        return $rpcenv->fork_worker($workername, $vmid, $authuser, $realcmd);
    },
});

__PACKAGE__->register_method({
    name => 'vmdiridx',
    path => '{vmid}',
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
    permissions => {
        user => 'all',
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
        },
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {
                subdir => { type => 'string' },
            },
        },
        links => [{ rel => 'child', href => "{subdir}" }],
    },
    code => sub {
        my ($param) = @_;

        # test if VM exists
        my $conf = PVE::LXC::Config->load_config($param->{vmid});

        my $res = [
            { subdir => 'config' },
            { subdir => 'pending' },
            { subdir => 'status' },
            { subdir => 'vncproxy' },
            { subdir => 'termproxy' },
            { subdir => 'vncwebsocket' },
            { subdir => 'spiceproxy' },
            { subdir => 'migrate' },
            { subdir => 'clone' },
            #	    { subdir => 'initlog' },
            { subdir => 'rrd' },
            { subdir => 'rrddata' },
            { subdir => 'firewall' },
            { subdir => 'snapshot' },
            { subdir => 'resize' },
            { subdir => 'interfaces' },
        ];

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'rrd',
    path => '{vmid}/rrd',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Audit']],
    },
    description => "Read VM RRD statistics (returns PNG)",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            timeframe => {
                description => "Specify the time frame you are interested in.",
                type => 'string',
                enum => ['hour', 'day', 'week', 'month', 'year'],
            },
            ds => {
                description => "The list of datasources you want to display.",
                type => 'string',
                format => 'pve-configid-list',
            },
            cf => {
                description => "The RRD consolidation function",
                type => 'string',
                enum => ['AVERAGE', 'MAX'],
                optional => 1,
            },
        },
    },
    returns => {
        type => "object",
        properties => {
            filename => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        return PVE::RRD::create_rrd_graph(
            "pve-vm-9.0/$param->{vmid}", $param->{timeframe}, $param->{ds}, $param->{cf},
        );
    },
});

__PACKAGE__->register_method({
    name => 'rrddata',
    path => '{vmid}/rrddata',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Audit']],
    },
    description => "Read VM RRD statistics",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            timeframe => {
                description => "Specify the time frame you are interested in.",
                type => 'string',
                enum => ['hour', 'day', 'week', 'month', 'year'],
            },
            cf => {
                description => "The RRD consolidation function",
                type => 'string',
                enum => ['AVERAGE', 'MAX'],
                optional => 1,
            },
        },
    },
    returns => {
        type => "array",
        items => {
            type => "object",
            properties => {},
        },
    },
    code => sub {
        my ($param) = @_;

        return PVE::RRD::create_rrd_data(
            "pve-vm-9.0/$param->{vmid}", $param->{timeframe}, $param->{cf},
        );
    },
});

__PACKAGE__->register_method({
    name => 'destroy_vm',
    path => '{vmid}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Destroy the container (also delete all uses files).",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option(
                'pve-vmid',
                { completion => \&PVE::LXC::complete_ctid_stopped },
            ),
            force => {
                type => 'boolean',
                description => "Force destroy, even if running.",
                default => 0,
                optional => 1,
            },
            purge => {
                type => 'boolean',
                description => "Remove container from all related configurations."
                    . " For example, backup jobs, replication jobs or HA."
                    . " Related ACLs and Firewall entries will *always* be removed.",
                default => 0,
                optional => 1,
            },
            'destroy-unreferenced-disks' => {
                type => 'boolean',
                description => "If set, destroy additionally all disks with the VMID from all"
                    . " enabled storages which are not referenced in the config.",
                optional => 1,
            },
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();
        my $vmid = $param->{vmid};

        # test if container exists

        my $conf = PVE::LXC::Config->load_config($vmid);
        my $early_checks = sub {
            my ($conf) = @_;
            PVE::LXC::Config->check_protection($conf, "can't remove CT $vmid");
            PVE::LXC::Config->check_lock($conf);

            my $ha_managed = PVE::HA::Config::service_is_configured("ct:$vmid");

            if (!$param->{purge}) {
                die
                    "unable to remove CT $vmid - used in HA resources and purge parameter not set.\n"
                    if $ha_managed;

                # do not allow destroy if there are replication jobs without purge
                my $repl_conf = PVE::ReplicationConfig->new();
                $repl_conf->check_for_existing_jobs($vmid);
            }

            return $ha_managed;
        };

        $early_checks->($conf);

        my $running_error_msg = "unable to destroy CT $vmid - container is running\n";
        die $running_error_msg if !$param->{force} && PVE::LXC::check_running($vmid); # check early

        my $code = sub {
            # reload config after lock
            $conf = PVE::LXC::Config->load_config($vmid);
            my $ha_managed = $early_checks->($conf);

            if (PVE::LXC::check_running($vmid)) {
                die $running_error_msg if !$param->{force};
                warn "forced to stop CT $vmid before destroying!\n";
                if (!$ha_managed) {
                    PVE::LXC::vm_stop($vmid, 1);
                } else {
                    run_command(['ha-manager', 'crm-command', 'stop', "ct:$vmid", '120']);
                }
            }

            my $storage_cfg = cfs_read_file("storage.cfg");
            PVE::LXC::destroy_lxc_container(
                $storage_cfg,
                $vmid,
                $conf,
                { lock => 'destroyed' },
                $param->{'destroy-unreferenced-disks'},
            );

            PVE::AccessControl::remove_vm_access($vmid);
            PVE::Firewall::remove_vmfw_conf($vmid);
            if ($param->{purge}) {
                print "purging CT $vmid from related configurations..\n";
                PVE::ReplicationConfig::remove_vmid_jobs($vmid);
                PVE::VZDump::Plugin::remove_vmid_from_backup_jobs($vmid);

                if ($ha_managed) {
                    PVE::HA::Config::delete_service_from_config("ct:$vmid", $param->{purge});
                    print "NOTE: removed CT $vmid from HA resource configuration.\n";
                }
            }

            # only now remove the zombie config, else we can have reuse race
            PVE::LXC::Config->destroy_config($vmid);
        };

        my $realcmd = sub { PVE::LXC::Config->lock_config($vmid, $code); };

        return $rpcenv->fork_worker('vzdestroy', $vmid, $authuser, $realcmd);
    },
});

my $sslcert;

__PACKAGE__->register_method({
    name => 'vncproxy',
    path => '{vmid}/vncproxy',
    method => 'POST',
    protected => 1,
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Console']],
    },
    description => "Creates a TCP VNC proxy connections.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            websocket => {
                optional => 1,
                type => 'boolean',
                description => "use websocket instead of standard VNC.",
            },
            width => {
                optional => 1,
                description => "sets the width of the console in pixels.",
                type => 'integer',
                minimum => 16,
                maximum => 4096,
            },
            height => {
                optional => 1,
                description => "sets the height of the console in pixels.",
                type => 'integer',
                minimum => 16,
                maximum => 2160,
            },
        },
    },
    returns => {
        additionalProperties => 0,
        properties => {
            user => { type => 'string' },
            ticket => { type => 'string' },
            cert => { type => 'string' },
            port => { type => 'integer' },
            upid => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $vmid = $param->{vmid};
        my $node = $param->{node};

        my $authpath = "/vms/$vmid";

        my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

        $sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
            if !$sslcert;

        my $family;
        my $remcmd = [];

        if ($node ne PVE::INotify::nodename()) {
            (undef, $family) = PVE::Cluster::remote_node_ip($node);
            my $sshinfo = PVE::SSHInfo::get_ssh_info($node);
            $remcmd = PVE::SSHInfo::ssh_info_to_command($sshinfo, '-t');
        } else {
            $family = PVE::Tools::get_host_address_family($node);
        }

        my $port = PVE::Tools::next_vnc_port($family);

        my $conf = PVE::LXC::Config->load_config($vmid, $node);
        my $concmd = PVE::LXC::get_console_command($vmid, $conf, -1);

        my $shcmd = [
            '/usr/bin/dtach',
            '-A',
            "/var/run/dtach/vzctlconsole$vmid",
            '-r',
            'winch',
            '-z',
            @$concmd,
        ];

        my $realcmd = sub {
            my $upid = shift;

            syslog('info', "starting lxc vnc proxy $upid\n");

            my $timeout = 10;

            my $cmd = [
                '/usr/bin/vncterm',
                '-rfbport',
                $port,
                '-timeout',
                $timeout,
                '-authpath',
                $authpath,
                '-perm',
                'VM.Console',
            ];

            if ($param->{width}) {
                push @$cmd, '-width', $param->{width};
            }

            if ($param->{height}) {
                push @$cmd, '-height', $param->{height};
            }

            if ($param->{websocket}) {
                $ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm
                push @$cmd, '-notls', '-listen', 'localhost';
            }

            push @$cmd, '-c', @$remcmd, @$shcmd;

            run_command($cmd, keeplocale => 1);

            return;
        };

        my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd);

        PVE::Tools::wait_for_vnc_port($port);

        return {
            user => $authuser,
            ticket => $ticket,
            port => $port,
            upid => $upid,
            cert => $sslcert,
        };
    },
});

__PACKAGE__->register_method({
    name => 'termproxy',
    path => '{vmid}/termproxy',
    method => 'POST',
    protected => 1,
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Console']],
    },
    description => "Creates a TCP proxy connection.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
        },
    },
    returns => {
        additionalProperties => 0,
        properties => {
            user => { type => 'string' },
            ticket => { type => 'string' },
            port => { type => 'integer' },
            upid => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $vmid = $param->{vmid};
        my $node = $param->{node};

        my $authpath = "/vms/$vmid";

        my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

        my $family;
        my $remcmd = [];

        if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
            (undef, $family) = PVE::Cluster::remote_node_ip($node);
            my $sshinfo = PVE::SSHInfo::get_ssh_info($node);
            $remcmd = PVE::SSHInfo::ssh_info_to_command($sshinfo, '-t');
        } else {
            $family = PVE::Tools::get_host_address_family($node);
        }

        my $port = PVE::Tools::next_vnc_port($family);

        my $conf = PVE::LXC::Config->load_config($vmid, $node);
        my $concmd = PVE::LXC::get_console_command($vmid, $conf, -1);

        my $shcmd = [
            '/usr/bin/dtach',
            '-A',
            "/var/run/dtach/vzctlconsole$vmid",
            '-r',
            'winch',
            '-z',
            @$concmd,
        ];

        my $realcmd = sub {
            my $upid = shift;

            syslog('info', "starting lxc termproxy $upid\n");

            my $cmd =
                ['/usr/bin/termproxy', $port, '--path', $authpath, '--perm', 'VM.Console', '--'];
            push @$cmd, @$remcmd, @$shcmd;

            PVE::Tools::run_command($cmd);
        };

        my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd, 1);

        PVE::Tools::wait_for_vnc_port($port);

        return {
            user => $authuser,
            ticket => $ticket,
            port => $port,
            upid => $upid,
        };
    },
});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => '{vmid}/vncwebsocket',
    method => 'GET',
    permissions => {
        description => "You also need to pass a valid ticket (vncticket).",
        check => ['perm', '/vms/{vmid}', ['VM.Console']],
    },
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            vncticket => {
                description => "Ticket from previous call to vncproxy.",
                type => 'string',
                maxLength => 512,
            },
            port => {
                description => "Port number returned by previous vncproxy call.",
                type => 'integer',
                minimum => 5900,
                maximum => 5999,
            },
        },
    },
    returns => {
        type => "object",
        properties => {
            port => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $authpath = "/vms/$param->{vmid}";

        PVE::AccessControl::verify_vnc_ticket($param->{vncticket}, $authuser, $authpath);

        my $port = $param->{port};

        return { port => $port };
    },
});

__PACKAGE__->register_method({
    name => 'spiceproxy',
    path => '{vmid}/spiceproxy',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Console']],
    },
    description => "Returns a SPICE configuration to connect to the CT.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            proxy => get_standard_option('spice-proxy', { optional => 1 }),
        },
    },
    returns => get_standard_option('remote-viewer-config'),
    code => sub {
        my ($param) = @_;

        my $vmid = $param->{vmid};
        my $node = $param->{node};
        my $proxy = $param->{proxy};

        my $authpath = "/vms/$vmid";
        my $permissions = 'VM.Console';

        my $conf = PVE::LXC::Config->load_config($vmid);

        die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

        my $concmd = PVE::LXC::get_console_command($vmid, $conf);

        my $shcmd = [
            '/usr/bin/dtach',
            '-A',
            "/var/run/dtach/vzctlconsole$vmid",
            '-r',
            'winch',
            '-z',
            @$concmd,
        ];

        my $title = "CT $vmid";

        return PVE::API2Tools::run_spiceterm(
            $authpath, $permissions, $vmid, $node, $proxy, $title, $shcmd,
        );
    },
});

__PACKAGE__->register_method({
    name => 'remote_migrate_vm',
    path => '{vmid}/remote_migrate',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description =>
        "Migrate the container to another cluster. Creates a new migration task. EXPERIMENTAL feature!",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Migrate']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            'target-vmid' => get_standard_option('pve-vmid', { optional => 1 }),
            'target-endpoint' => get_standard_option('proxmox-remote', {
                    description => "Remote target endpoint",
            }),
            online => {
                type => 'boolean',
                description => "Use online/live migration.",
                optional => 1,
            },
            restart => {
                type => 'boolean',
                description => "Use restart migration",
                optional => 1,
            },
            timeout => {
                type => 'integer',
                description => "Timeout in seconds for shutdown for restart migration",
                optional => 1,
                default => 180,
            },
            delete => {
                type => 'boolean',
                description =>
                    "Delete the original CT and related data after successful migration. By default the original CT is kept on the source cluster in a stopped state.",
                optional => 1,
                default => 0,
            },
            'target-storage' => get_standard_option('pve-targetstorage', {
                    optional => 0,
            }),
            'target-bridge' => {
                type => 'string',
                description =>
                    "Mapping from source to target bridges. Providing only a single bridge ID maps all source bridges to that bridge. Providing the special value '1' will map each source bridge to itself.",
                format => 'bridge-pair-list',
            },
            bwlimit => {
                description => "Override I/O bandwidth limit (in KiB/s).",
                optional => 1,
                type => 'number',
                minimum => '0',
                default => 'migrate limit from datacenter or storage config',
            },
        },
    },
    returns => {
        type => 'string',
        description => "the task ID.",
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $source_vmid = extract_param($param, 'vmid');
        my $target_endpoint = extract_param($param, 'target-endpoint');
        my $target_vmid = extract_param($param, 'target-vmid') // $source_vmid;

        my $delete = extract_param($param, 'delete') // 0;

        PVE::Cluster::check_cfs_quorum();

        # test if CT exists
        my $conf = PVE::LXC::Config->load_config($source_vmid);
        PVE::LXC::Config->check_lock($conf);

        # try to detect errors early
        if (PVE::LXC::check_running($source_vmid)) {
            die "can't migrate running container without --online or --restart\n"
                if !$param->{online} && !$param->{restart};
        }

        raise_param_exc({ vmid => "cannot migrate HA-managed CT to remote cluster" })
            if PVE::HA::Config::vm_is_ha_managed($source_vmid);

        my $remote = PVE::JSONSchema::parse_property_string('proxmox-remote', $target_endpoint);

        # TODO: move this as helper somewhere appropriate?
        my $conn_args = {
            protocol => 'https',
            host => $remote->{host},
            port => $remote->{port} // 8006,
            apitoken => $remote->{apitoken},
        };

        my $fp;
        if ($fp = $remote->{fingerprint}) {
            $conn_args->{cached_fingerprints} = { uc($fp) => 1 };
        }

        print "Establishing API connection with remote at '$remote->{host}'\n";

        my $api_client = PVE::APIClient::LWP->new(%$conn_args);

        if (!defined($fp)) {
            my $cert_info = $api_client->get("/nodes/localhost/certificates/info");
            foreach my $cert (@$cert_info) {
                my $filename = $cert->{filename};
                next if $filename ne 'pveproxy-ssl.pem' && $filename ne 'pve-ssl.pem';
                $fp = $cert->{fingerprint} if !$fp || $filename eq 'pveproxy-ssl.pem';
            }
            $conn_args->{cached_fingerprints} = { uc($fp) => 1 }
                if defined($fp);
        }

        my $storecfg = PVE::Storage::config();
        my $target_storage = extract_param($param, 'target-storage');
        my $storagemap =
            eval { PVE::JSONSchema::parse_idmap($target_storage, 'pve-storage-id') };
        raise_param_exc({ 'target-storage' => "failed to parse storage map: $@" })
            if $@;

        my $target_bridge = extract_param($param, 'target-bridge');
        my $bridgemap = eval { PVE::JSONSchema::parse_idmap($target_bridge, 'pve-bridge-id') };
        raise_param_exc({ 'target-bridge' => "failed to parse bridge map: $@" })
            if $@;

        die "remote migration requires explicit storage mapping!\n"
            if $storagemap->{identity};

        $param->{storagemap} = $storagemap;
        $param->{bridgemap} = $bridgemap;
        $param->{remote} = {
            conn => $conn_args, # re-use fingerprint for tunnel
            client => $api_client,
            vmid => $target_vmid,
        };
        $param->{migration_type} = 'websocket';
        $param->{delete} = $delete if $delete;

        my $cluster_status = $api_client->get("/cluster/status");
        my $target_node;
        foreach my $entry (@$cluster_status) {
            next if $entry->{type} ne 'node';
            if ($entry->{local}) {
                $target_node = $entry->{name};
                last;
            }
        }

        die "couldn't determine endpoint's node name\n"
            if !defined($target_node);

        my $realcmd = sub {
            PVE::LXC::Migrate->migrate($target_node, $remote->{host}, $source_vmid, $param);
        };

        my $worker = sub {
            return PVE::GuestHelpers::guest_migration_lock($source_vmid, 10, $realcmd);
        };

        return $rpcenv->fork_worker('vzmigrate', $source_vmid, $authuser, $worker);
    },
});

__PACKAGE__->register_method({
    name => 'migrate_vm_precondition',
    path => '{vmid}/migrate',
    method => 'GET',
    protected => 1,
    proxyto => 'node',
    description => "Get preconditions for migration.",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Migrate']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            target => get_standard_option(
                'pve-node',
                {
                    description => "Target node.",
                    completion => \&PVE::Cluster::complete_migration_target,
                    optional => 1,
                },
            ),
        },
    },
    returns => {
        type => "object",
        properties => {
            running => {
                type => 'boolean',
                description => "Determines if the container is running.",
            },
            'allowed-nodes' => {
                type => 'array',
                items => {
                    type => 'string',
                    description => "An allowed node",
                },
                optional => 1,
                description => "List of nodes allowed for migration.",
            },
            'not-allowed-nodes' => {
                type => 'object',
                optional => 1,
                properties => {
                    'blocking-ha-resources' => {
                        description => "HA resources, which are blocking the"
                            . " container from being migrated to the node.",
                        type => 'array',
                        optional => 1,
                        items => {
                            description => "A blocking HA resource",
                            type => 'object',
                            properties => {
                                sid => {
                                    type => 'string',
                                    description => "The blocking HA resource id",
                                },
                                cause => {
                                    type => 'string',
                                    description => "The reason why the HA"
                                        . " resource is blocking the migration.",
                                    enum => ['resource-affinity'],
                                },
                            },
                        },
                    },
                },
                description => "List of not allowed nodes with additional information.",
            },
            'dependent-ha-resources' => {
                description => "HA resources, which will be migrated to the same target node as"
                    . " the VM, because these are in positive affinity with the VM.",
                type => 'array',
                optional => 1,
                items => {
                    type => 'string',
                    description => "The '<ty>:<id>' resource IDs of a HA resource with a"
                        . " positive affinity rule to this CT.",
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        PVE::Cluster::check_cfs_quorum();

        my $res = {};

        my $vmid = extract_param($param, 'vmid');
        my $target = extract_param($param, 'target');
        my $localnode = PVE::INotify::nodename();

        # test if VM exists
        my $vmconf = PVE::LXC::Config->load_config($vmid);
        my $storecfg = PVE::Storage::config();

        # try to detect errors early
        PVE::LXC::Config->check_lock($vmconf);

        $res->{running} = PVE::LXC::check_running($vmid) ? 1 : 0;

        $res->{'allowed-nodes'} = [];
        $res->{'not-allowed-nodes'} = {};

        my $blocking_ha_resources_by_node = {};

        if (PVE::HA::Config::vm_is_ha_managed($vmid)) {
            (my $dependent_ha_resource, $blocking_ha_resources_by_node) =
                PVE::HA::Config::get_resource_motion_info("ct:$vmid");

            $res->{'dependent-ha-resources'} = $dependent_ha_resource // [];
        }

        my $nodelist = PVE::Cluster::get_nodelist();
        for my $node ($nodelist->@*) {
            next if $node eq $localnode;

            # extracting blocking resources for current node
            if (my $blocking_ha_resources = $blocking_ha_resources_by_node->{$node}) {
                $res->{'not-allowed-nodes'}->{$node}->{'blocking-ha-resources'} =
                    $blocking_ha_resources;
            }

            # if nothing came up, add it to the allowed nodes
            if (!defined($res->{'not-allowed-nodes'}->{$node})) {
                push $res->{'allowed-nodes'}->@*, $node;
            }
        }

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'migrate_vm',
    path => '{vmid}/migrate',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Migrate the container to another node. Creates a new migration task.",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Migrate']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            target => get_standard_option(
                'pve-node',
                {
                    description => "Target node.",
                    completion => \&PVE::Cluster::complete_migration_target,
                },
            ),
            'target-storage' => get_standard_option('pve-targetstorage'),
            online => {
                type => 'boolean',
                description => "Use online/live migration.",
                optional => 1,
            },
            restart => {
                type => 'boolean',
                description => "Use restart migration",
                optional => 1,
            },
            timeout => {
                type => 'integer',
                description => "Timeout in seconds for shutdown for restart migration",
                optional => 1,
                default => 180,
            },
            bwlimit => {
                description => "Override I/O bandwidth limit (in KiB/s).",
                optional => 1,
                type => 'number',
                minimum => '0',
                default => 'migrate limit from datacenter or storage config',
            },
        },
    },
    returns => {
        type => 'string',
        description => "the task ID.",
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $target = extract_param($param, 'target');

        my $localnode = PVE::INotify::nodename();
        raise_param_exc({ target => "target is local node." }) if $target eq $localnode;

        PVE::Cluster::check_cfs_quorum();

        PVE::Cluster::check_node_exists($target);

        my $targetip = PVE::Cluster::remote_node_ip($target);

        my $vmid = extract_param($param, 'vmid');

        # test if VM exists
        PVE::LXC::Config->load_config($vmid);

        # try to detect errors early
        if (PVE::LXC::check_running($vmid)) {
            die "can't migrate running container without --online or --restart\n"
                if !$param->{online} && !$param->{restart};
        }

        if (my $targetstorage = delete $param->{'target-storage'}) {
            my $storecfg = PVE::Storage::config();
            my $storagemap =
                eval { PVE::JSONSchema::parse_idmap($targetstorage, 'pve-storage-id') };
            raise_param_exc({ 'target-storage' => "failed to parse storage map: $@" })
                if $@;

            $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk'])
                if !defined($storagemap->{identity});

            foreach my $target_sid (values %{ $storagemap->{entries} }) {
                $check_storage_access_migrate->(
                    $rpcenv, $authuser, $storecfg, $target_sid, $target,
                );
            }

            $check_storage_access_migrate->(
                $rpcenv, $authuser, $storecfg, $storagemap->{default}, $target,
            ) if $storagemap->{default};

            $param->{storagemap} = $storagemap;
        }

        if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

            my $hacmd = sub {
                my $upid = shift;

                my $service = "ct:$vmid";

                my $cmd = ['ha-manager', 'migrate', $service, $target];

                print "Requesting HA migration for CT $vmid to node $target\n";

                PVE::Tools::run_command($cmd);

                return;
            };

            return $rpcenv->fork_worker('hamigrate', $vmid, $authuser, $hacmd);

        } else {

            my $realcmd = sub {
                PVE::LXC::Migrate->migrate($target, $targetip, $vmid, $param);
            };

            my $worker = sub {
                return PVE::GuestHelpers::guest_migration_lock($vmid, 10, $realcmd);
            };

            return $rpcenv->fork_worker('vzmigrate', $vmid, $authuser, $worker);
        }
    },
});

__PACKAGE__->register_method({
    name => 'vm_feature',
    path => '{vmid}/feature',
    method => 'GET',
    proxyto => 'node',
    protected => 1,
    description => "Check if feature for virtual machine is available.",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            feature => {
                description => "Feature to check.",
                type => 'string',
                enum => ['snapshot', 'clone', 'copy'],
            },
            snapname => get_standard_option('pve-snapshot-name', {
                    optional => 1,
            }),
        },
    },
    returns => {
        type => "object",
        properties => {
            hasFeature => { type => 'boolean' },
            #nodes => {
            #type => 'array',
            #items => { type => 'string' },
            #}
        },
    },
    code => sub {
        my ($param) = @_;

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        my $snapname = extract_param($param, 'snapname');

        my $feature = extract_param($param, 'feature');

        my $conf = PVE::LXC::Config->load_config($vmid);

        if ($snapname) {
            my $snap = $conf->{snapshots}->{$snapname};
            die "snapshot '$snapname' does not exist\n" if !defined($snap);
            $conf = $snap;
        }
        my $storage_cfg = PVE::Storage::config();
        #Maybe include later
        #my $nodelist = PVE::LXC::shared_nodes($conf, $storage_cfg);
        my $hasFeature =
            PVE::LXC::Config->has_feature($feature, $conf, $storage_cfg, $snapname);

        return {
            hasFeature => $hasFeature,
            #nodes => [ keys %$nodelist ],
        };
    },
});

__PACKAGE__->register_method({
    name => 'template',
    path => '{vmid}/template',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a Template.",
    permissions => {
        description => "You need 'VM.Allocate' permissions on /vms/{vmid}",
        check => ['perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option(
                'pve-vmid',
                { completion => \&PVE::LXC::complete_ctid_stopped },
            ),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        my $updatefn = sub {

            my $conf = PVE::LXC::Config->load_config($vmid);
            PVE::LXC::Config->check_lock($conf);

            die "unable to create template, because CT contains snapshots\n"
                if $conf->{snapshots} && scalar(keys %{ $conf->{snapshots} });

            die "you can't convert a template to a template\n"
                if PVE::LXC::Config->is_template($conf);

            die "you can't convert a CT to template if the CT is running\n"
                if PVE::LXC::check_running($vmid);

            my $realcmd = sub {
                PVE::LXC::template_create($vmid, $conf);

                $conf->{template} = 1;

                PVE::LXC::Config->write_config($vmid, $conf);
                # and remove lxc config
                PVE::LXC::update_lxc_config($vmid, $conf);
            };

            return $rpcenv->fork_worker('vztemplate', $vmid, $authuser, $realcmd);
        };

        PVE::LXC::Config->lock_config($vmid, $updatefn);

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'clone_vm',
    path => '{vmid}/clone',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a container clone/copy",
    permissions => {
        description => "You need 'VM.Clone' permissions on /vms/{vmid}, "
            . "and 'VM.Allocate' permissions "
            . "on /vms/{newid} (or on the VM pool /pool/{pool}). You also need "
            . "'Datastore.AllocateSpace' on any used storage, and 'SDN.Use' on any bridge.",
        check => [
            'and',
            ['perm', '/vms/{vmid}', ['VM.Clone']],
            [
                'or',
                ['perm', '/vms/{newid}', ['VM.Allocate']],
                ['perm', '/pool/{pool}', ['VM.Allocate'], require_param => 'pool'],
            ],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            newid => get_standard_option(
                'pve-vmid',
                {
                    completion => \&PVE::Cluster::complete_next_vmid,
                    description => 'VMID for the clone.',
                },
            ),
            hostname => {
                optional => 1,
                type => 'string',
                format => 'dns-name',
                description => "Set a hostname for the new CT.",
            },
            description => {
                optional => 1,
                type => 'string',
                description => "Description for the new CT.",
            },
            pool => {
                optional => 1,
                type => 'string',
                format => 'pve-poolid',
                description => "Add the new CT to the specified pool.",
            },
            snapname => get_standard_option('pve-snapshot-name', {
                    optional => 1,
            }),
            storage => get_standard_option(
                'pve-storage-id',
                {
                    description => "Target storage for full clone.",
                    completion => \&PVE::LXC::complete_storage,
                    optional => 1,
                },
            ),
            full => {
                optional => 1,
                type => 'boolean',
                description => "Create a full copy of all disks. This is always done when "
                    . "you clone a normal CT. For CT templates, we try to create a linked clone by default.",
            },
            target => get_standard_option(
                'pve-node',
                {
                    description =>
                        "Target node. Only allowed if the original VM is on shared storage.",
                    optional => 1,
                },
            ),
            bwlimit => {
                description => "Override I/O bandwidth limit (in KiB/s).",
                optional => 1,
                type => 'number',
                minimum => '0',
                default => 'clone limit from datacenter or storage config',
            },
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');
        my $vmid = extract_param($param, 'vmid');
        my $newid = extract_param($param, 'newid');
        my $pool = extract_param($param, 'pool');
        if (defined($pool)) {
            $rpcenv->check_pool_exist($pool);
        }
        my $snapname = extract_param($param, 'snapname');
        my $storage = extract_param($param, 'storage');
        my $target = extract_param($param, 'target');
        my $localnode = PVE::INotify::nodename();

        undef $target if $target && ($target eq $localnode || $target eq 'localhost');

        PVE::Cluster::check_node_exists($target) if $target;

        my $storecfg = PVE::Storage::config();

        if ($storage) {
            # check if storage is enabled on local node
            PVE::Storage::storage_check_enabled($storecfg, $storage);
            if ($target) {
                # check if storage is available on target node
                PVE::Storage::storage_check_enabled($storecfg, $storage, $target);
                # clone only works if target storage is shared
                my $scfg = PVE::Storage::storage_config($storecfg, $storage);
                die "can't clone to non-shared storage '$storage'\n" if !$scfg->{shared};
            }
        }

        PVE::Cluster::check_cfs_quorum();

        my $newconf = {};
        my $mountpoints = {};
        my $fullclone = {};
        my $vollist = [];
        my $running;

        my $lock_and_reload = sub {
            my ($vmid, $code) = @_;
            return PVE::LXC::Config->lock_config(
                $vmid,
                sub {
                    my $conf = PVE::LXC::Config->load_config($vmid);
                    die "Lost 'create' config lock, aborting.\n"
                        if !PVE::LXC::Config->has_lock($conf, 'create');

                    return $code->($conf);
                },
            );
        };

        my $src_conf = PVE::LXC::Config->set_lock($vmid, 'disk');

        eval { PVE::LXC::Config->create_and_lock_config($newid, 0); };
        if (my $err = $@) {
            eval { PVE::LXC::Config->remove_lock($vmid, 'disk') };
            warn "Failed to remove source CT config lock - $@\n" if $@;

            die $err;
        }

        eval {
            $running = PVE::LXC::check_running($vmid) || 0;

            my $full = extract_param($param, 'full');
            if (!defined($full)) {
                $full = !PVE::LXC::Config->is_template($src_conf);
            }

            PVE::Firewall::clone_vmfw_conf($vmid, $newid);

            die "parameter 'storage' not allowed for linked clones\n"
                if defined($storage) && !$full;

            die "snapshot '$snapname' does not exist\n"
                if $snapname && !defined($src_conf->{snapshots}->{$snapname});

            my $src_conf = $snapname ? $src_conf->{snapshots}->{$snapname} : $src_conf;

            my $sharedvm = 1;
            for my $opt (sort keys %$src_conf) {
                next if $opt =~ m/^unused\d+$/;

                my $value = $src_conf->{$opt};

                if (($opt eq 'rootfs') || ($opt =~ m/^mp\d+$/)) {
                    my $mp = PVE::LXC::Config->parse_volume($opt, $value);

                    if ($mp->{type} eq 'volume') {
                        my $volid = $mp->{volume};

                        my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
                        $sid = $storage if defined($storage);
                        my $scfg = PVE::Storage::storage_config($storecfg, $sid);
                        if (!$scfg->{shared}) {
                            $sharedvm = 0;
                            warn "found non-shared volume: $volid\n" if $target;
                        }

                        $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

                        if ($full) {
                            die
                                "Cannot do full clones on a running container without snapshots\n"
                                if $running && !defined($snapname);
                            $fullclone->{$opt} = 1;
                        } else {
                            # not full means clone instead of copy
                            die "Linked clone feature for '$volid' is not available\n"
                                if !PVE::Storage::volume_has_feature(
                                    $storecfg,
                                    'clone',
                                    $volid,
                                    $snapname,
                                    $running,
                                    { 'valid_target_formats' => ['raw', 'subvol'] },
                                );
                        }

                        $mountpoints->{$opt} = $mp;
                        push @$vollist, $volid;

                    } else {
                        # TODO: allow bind mounts?
                        die "unable to clone mountpoint '$opt' (type $mp->{type})\n";
                    }
                } elsif ($opt =~ m/^net(\d+)$/) {
                    # always change MAC! address
                    my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
                    my $net = PVE::LXC::Config->parse_lxc_network($value);
                    $net->{hwaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
                    $newconf->{$opt} = PVE::LXC::Config->print_lxc_network($net);

                    PVE::LXC::check_bridge_access($rpcenv, $authuser, $newconf->{$opt});
                } else {
                    # copy everything else
                    $newconf->{$opt} = $value;
                }
            }
            die "can't clone CT to node '$target' (CT uses local storage)\n"
                if $target && !$sharedvm;

            # Replace the 'disk' lock with a 'create' lock.
            $newconf->{lock} = 'create';

            # delete all snapshot related config options
            delete $newconf->@{qw(snapshots parent snaptime snapstate)};

            delete $newconf->{pending};
            delete $newconf->{template};

            $newconf->{hostname} = $param->{hostname} if $param->{hostname};
            $newconf->{description} = $param->{description} if $param->{description};

            $lock_and_reload->(
                $newid,
                sub {
                    PVE::LXC::Config->write_config($newid, $newconf);
                },
            );
        };
        if (my $err = $@) {
            eval { PVE::LXC::Config->remove_lock($vmid, 'disk') };
            warn "Failed to remove source CT config lock - $@\n" if $@;

            eval {
                $lock_and_reload->(
                    $newid,
                    sub {
                        PVE::LXC::Config->destroy_config($newid);
                        PVE::Firewall::remove_vmfw_conf($newid);
                    },
                );
            };
            warn "Failed to remove target CT config - $@\n" if $@;

            die $err;
        }

        my $update_conf = sub {
            my ($key, $value) = @_;
            return $lock_and_reload->(
                $newid,
                sub {
                    my $conf = shift;
                    $conf->{$key} = $value;
                    PVE::LXC::Config->write_config($newid, $conf);
                },
            );
        };

        my $realcmd = sub {
            my ($upid) = @_;

            my $newvollist = [];

            my $verify_running = PVE::LXC::check_running($vmid) || 0;
            die "unexpected state change\n" if $verify_running != $running;

            eval {
                local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
                    sub { die "interrupted by signal\n"; };

                PVE::Storage::activate_volumes($storecfg, $vollist, $snapname);
                my $bwlimit = extract_param($param, 'bwlimit');

                foreach my $opt (keys %$mountpoints) {
                    my $mp = $mountpoints->{$opt};
                    my $volid = $mp->{volume};

                    my $newvolid;
                    if ($fullclone->{$opt}) {
                        print "create full clone of mountpoint $opt ($volid)\n";
                        my $source_storage = PVE::Storage::parse_volume_id($volid);
                        my $target_storage = $storage // $source_storage;
                        my $clonelimit = PVE::Storage::get_bandwidth_limit(
                            'clone', [$source_storage, $target_storage], $bwlimit,
                        );
                        $newvolid = PVE::LXC::copy_volume(
                            $mp,
                            $newid,
                            $target_storage,
                            $storecfg,
                            $newconf,
                            $snapname,
                            $clonelimit,
                        );
                    } else {
                        print "create linked clone of mount point $opt ($volid)\n";
                        $newvolid =
                            PVE::Storage::vdisk_clone($storecfg, $volid, $newid, $snapname);
                    }

                    push @$newvollist, $newvolid;
                    $mp->{volume} = $newvolid;

                    $update_conf->(
                        $opt,
                        PVE::LXC::Config->print_ct_mountpoint($mp, $opt eq 'rootfs'),
                    );
                }

                PVE::AccessControl::add_vm_to_pool($newid, $pool) if $pool;

                $lock_and_reload->(
                    $newid,
                    sub {
                        my $conf = shift;
                        my $rootdir = PVE::LXC::mount_all($newid, $storecfg, $conf, 1);

                        eval {
                            PVE::LXC::create_ifaces_ipams_ips($conf, $vmid);
                            my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir);
                            $lxc_setup->post_clone_hook($conf);
                        };
                        my $err = $@;
                        eval { PVE::LXC::umount_all($newid, $storecfg, $conf, 1); };
                        if ($err) {
                            warn "$@\n" if $@;
                            die $err;
                        } else {
                            die $@ if $@;
                        }
                    },
                );
            };
            my $err = $@;
            # Unlock the source config in any case:
            eval { PVE::LXC::Config->remove_lock($vmid, 'disk') };
            warn $@ if $@;

            if ($err) {
                # Now cleanup the config & disks & ipam:
                sleep 1; # some storages like rbd need to wait before release volume - really?

                foreach my $volid (@$newvollist) {
                    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
                    warn $@ if $@;
                }

                eval {
                    $lock_and_reload->(
                        $newid,
                        sub {
                            my $conf = shift;
                            PVE::LXC::delete_ifaces_ipams_ips($conf, $newid);
                            PVE::LXC::Config->destroy_config($newid);
                            PVE::Firewall::remove_vmfw_conf($newid);
                        },
                    );
                };
                warn "Failed to remove target CT config - $@\n" if $@;

                die "clone failed: $err";
            }

            $lock_and_reload->(
                $newid,
                sub {
                    PVE::LXC::Config->remove_lock($newid, 'create');

                    if ($target) {
                        # always deactivate volumes - avoid lvm LVs to be active on several nodes
                        PVE::Storage::deactivate_volumes($storecfg, $vollist, $snapname)
                            if !$running;
                        PVE::Storage::deactivate_volumes($storecfg, $newvollist);

                        PVE::LXC::Config->move_config_to_node($newid, $target);
                    }
                },
            );

            return;
        };

        return $rpcenv->fork_worker('vzclone', $vmid, $authuser, $realcmd);
    },
});

__PACKAGE__->register_method({
    name => 'resize_vm',
    path => '{vmid}/resize',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Resize a container mount point.",
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Config.Disk'], any => 1],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            disk => {
                type => 'string',
                description => "The disk you want to resize.",
                enum => [PVE::LXC::Config->valid_volume_keys()],
            },
            size => {
                type => 'string',
                pattern => '\+?\d+(\.\d+)?[KMGT]?',
                description =>
                    "The new size. With the '+' sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.",
            },
            digest => {
                type => 'string',
                description =>
                    'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
                maxLength => 40,
                optional => 1,
            },
        },
    },
    returns => {
        type => 'string',
        description => "the task ID.",
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        my $digest = extract_param($param, 'digest');

        my $sizestr = extract_param($param, 'size');
        my $ext = ($sizestr =~ s/^\+//);
        my $request_size = PVE::JSONSchema::parse_size($sizestr);
        die "invalid size string" if !defined($request_size);

        die "no options specified\n" if !scalar(keys %$param);

        my $storage_cfg = cfs_read_file("storage.cfg");

        my $load_and_check = sub {
            my $conf = PVE::LXC::Config->load_config($vmid);
            PVE::LXC::Config->check_lock($conf);

            PVE::LXC::check_ct_modify_config_perm(
                $rpcenv, $authuser, $vmid, undef, $conf, $param, [], $conf->{unprivileged},
            );

            PVE::Tools::assert_if_modified($digest, $conf->{digest});

            my $disk = $param->{disk};
            my $mp = PVE::LXC::Config->parse_volume($disk, $conf->{$disk});

            my $volid = $mp->{volume};

            my (undef, undef, $owner, undef, undef, undef, $format) =
                PVE::Storage::parse_volname($storage_cfg, $volid);

            die "can't resize mount point owned by another container ($owner)"
                if $vmid != $owner;

            my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

            $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

            PVE::Storage::activate_volumes($storage_cfg, [$volid]);

            my $size = PVE::Storage::volume_size_info($storage_cfg, $volid, 5);

            die "Could not determine current size of volume '$volid'\n" if !defined($size);

            my $newsize = $ext ? $size + $request_size : $request_size;
            $newsize = int($newsize);

            die "unable to shrink disk size\n" if $newsize < $size;

            die "disk is already at specified size\n" if $size == $newsize;

            return ($conf, $disk, $mp, $volid, $format, $newsize);
        };

        my $code = sub {
            my ($conf, $disk, $mp, $volid, $format, $newsize) = $load_and_check->();

            my $running = PVE::LXC::check_running($vmid);

            PVE::Cluster::log_msg(
                'info',
                $authuser,
                "update CT $vmid: resize --disk $disk --size $sizestr",
            );

            # Note: PVE::Storage::volume_resize doesn't do anything if $running=1, so
            # we pass 0 here (parameter only makes sense for qemu)
            PVE::Storage::volume_resize($storage_cfg, $volid, $newsize, 0);

            $mp->{size} = $newsize;
            $conf->{$disk} = PVE::LXC::Config->print_ct_mountpoint($mp, $disk eq 'rootfs');

            PVE::LXC::Config->write_config($vmid, $conf);

            if ($format eq 'raw') {
                # we need to ensure that the volume is mapped, if not needed this is a NOP
                my $path = PVE::Storage::map_volume($storage_cfg, $volid);
                $path = PVE::Storage::path($storage_cfg, $volid) if !defined($path);
                if ($running) {

                    $mp->{mp} = '/';
                    my $use_loopdev = (PVE::LXC::mountpoint_mount_path($mp, $storage_cfg))[1];
                    $path = PVE::LXC::query_loopdev($path) if $use_loopdev;
                    die
                        "internal error: CT running but mount point not attached to a loop device"
                        if !$path;
                    PVE::Tools::run_command(['losetup', '--set-capacity', $path])
                        if $use_loopdev;

                    # In order for resize2fs to know that we need online-resizing a mountpoint needs
                    # to be visible to it in its namespace.
                    # To not interfere with the rest of the system we unshare the current mount namespace,
                    # mount over /tmp and then run resize2fs.

                    # interestingly we don't need to e2fsck on mounted systems...
                    my $quoted = PVE::Tools::shellquote($path);
                    my $cmd =
                        "mount --make-rprivate / && mount $quoted /tmp && resize2fs $quoted";
                    eval { PVE::Tools::run_command([
                            'unshare', '-m', '--', 'sh', '-c', $cmd]); };
                    warn "Failed to update the container's filesystem: $@\n" if $@;
                } else {
                    eval {
                        PVE::Tools::run_command(['e2fsck', '-f', '-y', $path]);
                        PVE::Tools::run_command(['resize2fs', $path]);
                    };
                    warn "Failed to update the container's filesystem: $@\n" if $@;

                    # always un-map if not running, this is a NOP if not needed
                    PVE::Storage::unmap_volume($storage_cfg, $volid);
                }
            }
        };

        my $worker = sub {
            PVE::LXC::Config->lock_config($vmid, $code);
        };

        $load_and_check->(); # early checks before forking+locking

        return $rpcenv->fork_worker('resize', $vmid, $authuser, $worker);
    },
});

__PACKAGE__->register_method({
    name => 'move_volume',
    path => '{vmid}/move_volume',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description =>
        "Move a rootfs-/mp-volume to a different storage or to a different container.",
    permissions => {
        description => "You need 'VM.Config.Disk' permissions on /vms/{vmid}, "
            . "and 'Datastore.AllocateSpace' permissions on the storage. To move "
            . "a volume to another container, you need the permissions on the "
            . "target container as well.",
        check => ['perm', '/vms/{vmid}', ['VM.Config.Disk']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
            'target-vmid' => get_standard_option(
                'pve-vmid',
                {
                    completion => \&PVE::LXC::complete_ctid,
                    optional => 1,
                },
            ),
            volume => {
                type => 'string',
                #TODO: check how to handle unused mount points as the mp parameter is not configured
                enum => [PVE::LXC::Config->valid_volume_keys_with_unused()],
                description => "Volume which will be moved.",
            },
            storage => get_standard_option(
                'pve-storage-id',
                {
                    description => "Target Storage.",
                    completion => \&PVE::LXC::complete_storage,
                    optional => 1,
                },
            ),
            delete => {
                type => 'boolean',
                description =>
                    "Delete the original volume after successful copy. By default the "
                    . "original is kept as an unused volume entry.",
                optional => 1,
                default => 0,
            },
            digest => {
                type => 'string',
                description =>
                    'Prevent changes if current configuration file has different SHA1 " .
		    "digest. This can be used to prevent concurrent modifications.',
                maxLength => 40,
                optional => 1,
            },
            bwlimit => {
                description => "Override I/O bandwidth limit (in KiB/s).",
                optional => 1,
                type => 'number',
                minimum => '0',
                default => 'clone limit from datacenter or storage config',
            },
            'target-volume' => {
                type => 'string',
                description => "The config key the volume will be moved to. Default is the "
                    . "source volume key.",
                enum => [PVE::LXC::Config->valid_volume_keys_with_unused()],
                optional => 1,
            },
            'target-digest' => {
                type => 'string',
                description => 'Prevent changes if current configuration file of the target " .
		    "container has a different SHA1 digest. This can be used to prevent " .
		    "concurrent modifications.',
                maxLength => 40,
                optional => 1,
            },
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $vmid = extract_param($param, 'vmid');

        my $target_vmid = extract_param($param, 'target-vmid');

        my $storage = extract_param($param, 'storage');

        my $mpkey = extract_param($param, 'volume');

        my $target_mpkey = extract_param($param, 'target-volume') // $mpkey;

        my $digest = extract_param($param, 'digest');

        my $target_digest = extract_param($param, 'target-digest');

        my $lockname = 'disk';

        my ($mpdata, $old_volid);

        die "either set storage or target-vmid, but not both\n"
            if $storage && $target_vmid;

        my $storecfg = PVE::Storage::config();

        my $move_to_storage_checks = sub {
            PVE::LXC::Config->lock_config(
                $vmid,
                sub {
                    my $conf = PVE::LXC::Config->load_config($vmid);
                    PVE::LXC::Config->check_lock($conf);

                    die "cannot move volumes of a running container\n"
                        if PVE::LXC::check_running($vmid);

                    if ($mpkey =~ m/^unused\d+$/) {
                        die
                            "cannot move volume '$mpkey', only configured volumes can be moved to "
                            . "another storage\n";
                    }

                    $mpdata = PVE::LXC::Config->parse_volume($mpkey, $conf->{$mpkey});
                    $old_volid = $mpdata->{volume};

                    die "you can't move a volume with snapshots and delete the source\n"
                        if $param->{delete}
                        && PVE::LXC::Config->is_volume_in_use_by_snapshots($conf, $old_volid);

                    PVE::Tools::assert_if_modified($digest, $conf->{digest});

                    PVE::LXC::Config->set_lock($vmid, $lockname);
                },
            );
        };

        my $storage_realcmd = sub {
            eval {
                PVE::Cluster::log_msg(
                    'info',
                    $authuser,
                    "move volume CT $vmid: move --volume $mpkey --storage $storage",
                );

                my $conf = PVE::LXC::Config->load_config($vmid);
                my $storage_cfg = PVE::Storage::config();

                my $new_volid;

                eval {
                    PVE::Storage::activate_volumes($storage_cfg, [$old_volid]);
                    my $bwlimit = extract_param($param, 'bwlimit');
                    my $source_storage = PVE::Storage::parse_volume_id($old_volid);
                    my $movelimit = PVE::Storage::get_bandwidth_limit(
                        'move', [$source_storage, $storage], $bwlimit,
                    );
                    $new_volid = PVE::LXC::copy_volume(
                        $mpdata, $vmid, $storage, $storage_cfg, $conf, undef, $movelimit,
                    );
                    if (PVE::LXC::Config->is_template($conf)) {
                        PVE::Storage::activate_volumes($storage_cfg, [$new_volid]);
                        my $template_volid =
                            PVE::Storage::vdisk_create_base($storage_cfg, $new_volid);
                        $mpdata->{volume} = $template_volid;
                    } else {
                        $mpdata->{volume} = $new_volid;
                    }

                    PVE::LXC::Config->lock_config(
                        $vmid,
                        sub {
                            my $digest = $conf->{digest};
                            $conf = PVE::LXC::Config->load_config($vmid);
                            PVE::Tools::assert_if_modified($digest, $conf->{digest});

                            $conf->{$mpkey} = PVE::LXC::Config->print_ct_mountpoint(
                                $mpdata, $mpkey eq 'rootfs',
                            );

                            PVE::LXC::Config->add_unused_volume($conf, $old_volid)
                                if !$param->{delete};

                            PVE::LXC::Config->write_config($vmid, $conf);
                        },
                    );

                    eval {
                        # try to deactivate volumes - avoid lvm LVs to be active on several nodes
                        PVE::Storage::deactivate_volumes($storage_cfg, [$new_volid]);
                    };
                    warn $@ if $@;
                };
                if (my $err = $@) {
                    eval {
                        PVE::Storage::vdisk_free($storage_cfg, $new_volid)
                            if defined($new_volid);
                    };
                    warn $@ if $@;
                    die $err;
                }

                my $deactivated = 0;
                eval {
                    PVE::Storage::deactivate_volumes($storage_cfg, [$old_volid]);
                    $deactivated = 1;
                };
                warn $@ if $@;

                if ($param->{delete}) {
                    my $removed = 0;
                    if ($deactivated) {
                        eval {
                            PVE::Storage::vdisk_free($storage_cfg, $old_volid);
                            $removed = 1;
                        };
                        warn $@ if $@;
                    }
                    if (!$removed) {
                        PVE::LXC::Config->lock_config(
                            $vmid,
                            sub {
                                my $conf = PVE::LXC::Config->load_config($vmid);
                                PVE::LXC::Config->add_unused_volume($conf, $old_volid);
                                PVE::LXC::Config->write_config($vmid, $conf);
                            },
                        );
                    }
                }
            };
            my $err = $@;
            eval { PVE::LXC::Config->remove_lock($vmid, $lockname) };
            warn $@ if $@;
            die $err if $err;
        };

        my $load_and_check_reassign_configs = sub {
            my $vmlist = PVE::Cluster::get_vmlist()->{ids};

            die "Cannot move to/from 'rootfs'\n"
                if $mpkey eq "rootfs" || $target_mpkey eq "rootfs";

            if ($mpkey =~ m/^unused\d+$/ && $target_mpkey !~ m/^unused\d+$/) {
                die "Moving an unused volume to a used one is not possible\n";
            }
            die "could not find CT ${vmid}\n" if !exists($vmlist->{$vmid});
            die "could not find CT ${target_vmid}\n" if !exists($vmlist->{$target_vmid});

            my $source_node = $vmlist->{$vmid}->{node};
            my $target_node = $vmlist->{$target_vmid}->{node};

            die "Both containers need to be on the same node ($source_node != $target_node)\n"
                if $source_node ne $target_node;

            my $source_conf = PVE::LXC::Config->load_config($vmid);
            PVE::LXC::Config->check_lock($source_conf);
            my $target_conf;
            if ($target_vmid eq $vmid) {
                $target_conf = $source_conf;
            } else {
                $target_conf = PVE::LXC::Config->load_config($target_vmid);
                PVE::LXC::Config->check_lock($target_conf);
            }

            die "Can't move volumes from or to template CT\n"
                if ($source_conf->{template} || $target_conf->{template});

            if ($digest) {
                eval { PVE::Tools::assert_if_modified($digest, $source_conf->{digest}) };
                die "Container ${vmid}: $@" if $@;
            }

            if ($target_digest) {
                eval { PVE::Tools::assert_if_modified($target_digest, $target_conf->{digest}) };
                die "Container ${target_vmid}: $@" if $@;
            }

            die "volume '${mpkey}' for container '$vmid' does not exist\n"
                if !defined($source_conf->{$mpkey});

            die
                "Target volume key '${target_mpkey}' is already in use for container '$target_vmid'\n"
                if exists $target_conf->{$target_mpkey};

            my $drive = PVE::LXC::Config->parse_volume($mpkey, $source_conf->{$mpkey});
            my $source_volid = $drive->{volume}
                or die "Volume '${mpkey}' has no associated image\n";
            die "Cannot move volume used by a snapshot to another container\n"
                if PVE::LXC::Config->is_volume_in_use_by_snapshots($source_conf, $source_volid);
            die "Storage does not support moving of this disk to another container\n"
                if !PVE::Storage::volume_has_feature($storecfg, 'rename', $source_volid);
            die "Cannot move a bindmount or device mount to another container\n"
                if $drive->{type} ne "volume";
            die
                "Cannot move in-use volume while the source CT is running - detach or shutdown first\n"
                if PVE::LXC::check_running($vmid) && $mpkey !~ m/^unused\d+$/;

            my $repl_conf = PVE::ReplicationConfig->new();
            if ($repl_conf->check_for_existing_jobs($target_vmid, 1)) {
                my ($storeid, undef) = PVE::Storage::parse_volume_id($source_volid);
                my $format = (PVE::Storage::parse_volname($storecfg, $source_volid))[6];

                die
                    "Cannot move volume on storage '$storeid' to a replicated container - missing replication support\n"
                    if !PVE::Storage::storage_can_replicate($storecfg, $storeid, $format);
            }

            return ($source_conf, $target_conf, $drive);
        };

        my $logfunc = sub { print STDERR "$_[0]\n"; };

        my $volume_reassignfn = sub {
            return PVE::LXC::Config->lock_config(
                $vmid,
                sub {
                    return PVE::LXC::Config->lock_config(
                        $target_vmid,
                        sub {
                            my ($source_conf, $target_conf, $drive) =
                                $load_and_check_reassign_configs->();
                            my $source_volid = $drive->{volume};

                            my $target_unused = $target_mpkey =~ m/^unused\d+$/;

                            print
                                "moving volume '$mpkey' from container '$vmid' to '$target_vmid'\n";

                            my ($storage, $source_volname) =
                                PVE::Storage::parse_volume_id($source_volid);

                            my $fmt =
                                (PVE::Storage::parse_volname($storecfg, $source_volid))[6];

                            my $new_volid = PVE::Storage::rename_volume(
                                $storecfg, $source_volid, $target_vmid,
                            );

                            $drive->{volume} = $new_volid;

                            delete $source_conf->{$mpkey};
                            print
                                "removing volume '${mpkey}' from container '${vmid}' config\n";
                            PVE::LXC::Config->write_config($vmid, $source_conf);

                            my $drive_string;
                            if ($target_unused) {
                                $drive_string = $new_volid;
                            } else {
                                $drive_string =
                                    PVE::LXC::Config->print_volume($target_mpkey, $drive);
                            }

                            if ($target_unused) {
                                $target_conf->{$target_mpkey} = $drive_string;
                            } else {
                                my $running = PVE::LXC::check_running($target_vmid);
                                my $param = { $target_mpkey => $drive_string };
                                my $errors = PVE::LXC::Config->update_pct_config(
                                    $target_vmid, $target_conf, $running, $param,
                                );
                                $rpcenv->warn($errors->{$_}) for keys $errors->%*;
                            }

                            PVE::LXC::Config->write_config($target_vmid, $target_conf);
                            $target_conf = PVE::LXC::Config->load_config($target_vmid);

                            PVE::LXC::update_lxc_config($target_vmid, $target_conf)
                                if !$target_unused;
                            print
                                "target container '$target_vmid' updated with '$target_mpkey'\n";

                            # remove possible replication snapshots
                            if (PVE::Storage::volume_has_feature(
                                $storecfg,
                                'replicate',
                                $source_volid,
                            )) {
                                eval {
                                    PVE::Replication::prepare(
                                        $storecfg, [$new_volid], undef, 1, undef, $logfunc,
                                    );
                                };
                                if (my $err = $@) {
                                    $rpcenv->warn(
                                        "Failed to remove replication snapshots on volume "
                                            . "'${target_mpkey}'. Manual cleanup could be necessary. "
                                            . "Error: ${err}\n");
                                }
                            }
                        },
                    );
                },
            );
        };

        if ($target_vmid && $storage) {
            my $msg = "either set 'storage' or 'target-vmid', but not both";
            raise_param_exc({ 'target-vmid' => $msg, 'storage' => $msg });
        } elsif ($target_vmid) {
            $rpcenv->check_vm_perm($authuser, $target_vmid, undef, ['VM.Config.Disk'])
                if $authuser ne 'root@pam';

            my (undef, undef, $drive) = $load_and_check_reassign_configs->();
            my $storeid = PVE::Storage::parse_volume_id($drive->{volume});
            $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);
            return $rpcenv->fork_worker(
                'move_volume',
                "${vmid}-${mpkey}>${target_vmid}-${target_mpkey}",
                $authuser,
                $volume_reassignfn,
            );
        } elsif ($storage) {
            $rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace']);
            &$move_to_storage_checks();
            my $task =
                eval { $rpcenv->fork_worker('move_volume', $vmid, $authuser, $storage_realcmd); };
            if (my $err = $@) {
                eval { PVE::LXC::Config->remove_lock($vmid, $lockname) };
                warn $@ if $@;
                die $err;
            }
            return $task;
        } else {
            my $msg = "both 'storage' and 'target-vmid' missing, either needs to be set";
            raise_param_exc({ 'target-vmid' => $msg, 'storage' => $msg });
        }
    },
});

__PACKAGE__->register_method({
    name => 'vm_pending',
    path => '{vmid}/pending',
    method => 'GET',
    proxyto => 'node',
    description => 'Get container configuration, including pending changes.',
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
        },
    },
    returns => {
        type => "array",
        items => {
            type => "object",
            properties => {
                key => {
                    description => 'Configuration option name.',
                    type => 'string',
                },
                value => {
                    description => 'Current value.',
                    type => 'string',
                    optional => 1,
                },
                pending => {
                    description => 'Pending value.',
                    type => 'string',
                    optional => 1,
                },
                delete => {
                    description => "Indicates a pending delete request if present and not 0.",
                    type => 'integer',
                    minimum => 0,
                    maximum => 2,
                    optional => 1,
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $conf = PVE::LXC::Config->load_config($param->{vmid});

        my $pending_delete_hash =
            PVE::LXC::Config->parse_pending_delete($conf->{pending}->{delete});

        return PVE::GuestHelpers::config_with_pending_array($conf, $pending_delete_hash);
    },
});

__PACKAGE__->register_method({
    name => 'ip',
    path => '{vmid}/interfaces',
    method => 'GET',
    protected => 1,
    proxyto => 'node',
    permissions => {
        check => ['perm', '/vms/{vmid}', ['VM.Audit']],
    },
    description => 'Get IP addresses of the specified container interface.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid =>
                get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
        },
    },
    returns => {
        type => "array",
        items => {
            type => 'object',
            properties => {
                name => {
                    type => 'string',
                    description => 'The name of the interface',
                    optional => 0,
                },
                # TODO: deprecate on next major release
                hwaddr => {
                    type => 'string',
                    description => 'The MAC address of the interface',
                    optional => 0,
                },
                "hardware-address" => {
                    type => 'string',
                    description => 'The MAC address of the interface',
                    optional => 0,
                },
                # TODO: deprecate on next major release
                inet => {
                    type => 'string',
                    description => 'The IPv4 address of the interface',
                    optional => 1,
                },
                # TODO: deprecate on next major release
                inet6 => {
                    type => 'string',
                    description => 'The IPv6 address of the interface',
                    optional => 1,
                },
                "ip-addresses" => {
                    type => 'array',
                    description => 'The addresses of the interface',
                    optional => 0,
                    items => {
                        type => 'object',
                        properties => {
                            prefix => {
                                type => 'integer',
                                description => 'IP-Prefix',
                                optional => 1,
                            },
                            "ip-address" => {
                                type => 'string',
                                description => 'IP-Address',
                                optional => 1,
                            },
                            "ip-address-type" => {
                                type => 'string',
                                description => 'IP-Family',
                                optional => 1,
                            },
                        },
                    },
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        return PVE::LXC::get_interfaces($param->{vmid});
    },
});

__PACKAGE__->register_method({
    name => 'mtunnel',
    path => '{vmid}/mtunnel',
    method => 'POST',
    protected => 1,
    description => 'Migration tunnel endpoint - only for internal use by CT migration.',
    permissions => {
        check => [
            'and', ['perm', '/vms/{vmid}', ['VM.Allocate']], ['perm', '/', ['Sys.Incoming']],
        ],
        description => "You need 'VM.Allocate' permissions on '/vms/{vmid}' and Sys.Incoming"
            . " on '/'. Further permission checks happen during the actual migration.",
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            storages => {
                type => 'string',
                format => 'pve-storage-id-list',
                optional => 1,
                description =>
                    'List of storages to check permission and availability. Will be checked again for all actually used storages during migration.',
            },
            bridges => {
                type => 'string',
                format => 'pve-bridge-id-list',
                optional => 1,
                description =>
                    'List of network bridges to check availability. Will be checked again for actually used bridges during migration.',
            },
        },
    },
    returns => {
        additionalProperties => 0,
        properties => {
            upid => { type => 'string' },
            ticket => { type => 'string' },
            socket => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');
        my $vmid = extract_param($param, 'vmid');

        my $storages = extract_param($param, 'storages');
        my $bridges = extract_param($param, 'bridges');

        my $nodename = PVE::INotify::nodename();

        raise_param_exc({
            node => "node needs to be 'localhost' or local hostname '$nodename'" })
            if $node ne 'localhost' && $node ne $nodename;

        $node = $nodename;

        my $storecfg = PVE::Storage::config();
        foreach my $storeid (PVE::Tools::split_list($storages)) {
            $check_storage_access_migrate->($rpcenv, $authuser, $storecfg, $storeid, $node);
        }

        foreach my $bridge (PVE::Tools::split_list($bridges)) {
            PVE::Network::read_bridge_mtu($bridge);
        }

        PVE::Cluster::check_cfs_quorum();

        my $socket_addr = "/run/pve/ct-$vmid.mtunnel";

        my $lock = 'create';
        eval { PVE::LXC::Config->create_and_lock_config($vmid, 0, $lock); };

        raise_param_exc({ vmid => "unable to create empty CT config - $@" })
            if $@;

        my $realcmd = sub {
            my $state = {
                storecfg => PVE::Storage::config(),
                lock => $lock,
                vmid => $vmid,
            };

            my $run_locked = sub {
                my ($code, $params) = @_;
                return PVE::LXC::Config->lock_config(
                    $state->{vmid},
                    sub {
                        my $conf = PVE::LXC::Config->load_config($state->{vmid});

                        $state->{conf} = $conf;

                        die "Encountered wrong lock - aborting mtunnel command handling.\n"
                            if $state->{lock} && !PVE::LXC::Config->has_lock($conf, $state->{lock});

                        return $code->($params);
                    },
                );
            };

            my $cmd_desc = {
                config => {
                    conf => {
                        type => 'string',
                        description => 'Full CT config, adapted for target cluster/node',
                    },
                    'firewall-config' => {
                        type => 'string',
                        description => 'CT firewall config',
                        optional => 1,
                    },
                },
                ticket => {
                    path => {
                        type => 'string',
                        description =>
                            'socket path for which the ticket should be valid. must be known to current mtunnel instance.',
                    },
                },
                quit => {
                    cleanup => {
                        type => 'boolean',
                        description => 'remove CT config and volumes, aborting migration',
                        default => 0,
                    },
                },
                'disk-import' => $PVE::StorageTunnel::cmd_schema->{'disk-import'},
                'query-disk-import' => $PVE::StorageTunnel::cmd_schema->{'query-disk-import'},
                bwlimit => $PVE::StorageTunnel::cmd_schema->{bwlimit},
            };

            my $cmd_handlers = {
                'version' => sub {
                    # compared against other end's version
                    # bump/reset for breaking changes
                    # bump/bump for opt-in changes
                    return {
                        api => $PVE::LXC::Migrate::WS_TUNNEL_VERSION,
                        age => 0,
                    };
                },
                'config' => sub {
                    my ($params) = @_;

                    # parse and write out VM FW config if given
                    if (my $fw_conf = $params->{'firewall-config'}) {
                        my ($path, $fh) = PVE::Tools::tempfile_contents($fw_conf, 700);

                        my $empty_conf = {
                            rules => [],
                            options => {},
                            aliases => {},
                            ipset => {},
                            ipset_comments => {},
                        };
                        my $cluster_fw_conf = PVE::Firewall::load_clusterfw_conf();

                        # TODO: add flag for strict parsing?
                        # TODO: add import sub that does all this given raw content?
                        my $vmfw_conf = PVE::Firewall::generic_fw_config_parser(
                            $path, $cluster_fw_conf, $empty_conf, 'vm',
                        );
                        $vmfw_conf->{vmid} = $state->{vmid};
                        PVE::Firewall::save_vmfw_conf($state->{vmid}, $vmfw_conf);

                        $state->{cleanup}->{fw} = 1;
                    }

                    my $conf_fn = "incoming/lxc/$state->{vmid}.conf";
                    my $new_conf =
                        PVE::LXC::Config::parse_pct_config($conf_fn, $params->{conf}, 1);
                    delete $new_conf->{lock};
                    delete $new_conf->{digest};

                    my $unprivileged = delete $new_conf->{unprivileged};
                    my $arch = delete $new_conf->{arch};

                    # TODO handle properly?
                    delete $new_conf->{snapshots};
                    delete $new_conf->{parent};
                    delete $new_conf->{pending};
                    delete $new_conf->{lxc};

                    PVE::LXC::Config->remove_lock($state->{vmid}, 'create');

                    eval {
                        my $conf = {
                            unprivileged => $unprivileged,
                            arch => $arch,
                        };
                        $rpcenv->check($authuser, '/', ['Sys.Modify']) if !$unprivileged;
                        PVE::LXC::check_ct_modify_config_perm(
                            $rpcenv,
                            $authuser,
                            $state->{vmid},
                            undef,
                            $conf,
                            $new_conf,
                            undef,
                            $unprivileged,
                        );
                        my $errors = PVE::LXC::Config->update_pct_config(
                            $state->{vmid}, $conf, 0, $new_conf, [], [],
                        );
                        raise_param_exc($errors) if scalar(keys %$errors);
                        PVE::LXC::Config->write_config($state->{vmid}, $conf);
                        PVE::LXC::update_lxc_config($vmid, $conf);
                    };
                    if (my $err = $@) {
                        # revert to locked previous config
                        my $conf = PVE::LXC::Config->load_config($state->{vmid});
                        $conf->{lock} = 'create';
                        PVE::LXC::Config->write_config($state->{vmid}, $conf);

                        die $err;
                    }

                    my $conf = PVE::LXC::Config->load_config($state->{vmid});
                    $conf->{lock} = 'migrate';
                    PVE::LXC::Config->write_config($state->{vmid}, $conf);

                    $state->{lock} = 'migrate';

                    return;
                },
                'bwlimit' => sub {
                    my ($params) = @_;
                    return PVE::StorageTunnel::handle_bwlimit($params);
                },
                'disk-import' => sub {
                    my ($params) = @_;

                    $check_storage_access_migrate->(
                        $rpcenv, $authuser, $state->{storecfg}, $params->{storage}, $node,
                    );

                    $params->{unix} = "/run/pve/ct-$state->{vmid}.storage";

                    return PVE::StorageTunnel::handle_disk_import($state, $params);
                },
                'query-disk-import' => sub {
                    my ($params) = @_;

                    return PVE::StorageTunnel::handle_query_disk_import($state, $params);
                },
                'unlock' => sub {
                    PVE::LXC::Config->remove_lock($state->{vmid}, $state->{lock});
                    delete $state->{lock};
                    return;
                },
                'start' => sub {
                    PVE::LXC::vm_start(
                        $state->{vmid}, $state->{conf}, 0,
                    );

                    return;
                },
                'stop' => sub {
                    PVE::LXC::vm_stop($state->{vmid}, 1, 10, 1);
                    return;
                },
                'ticket' => sub {
                    my ($params) = @_;

                    my $path = $params->{path};

                    die "Not allowed to generate ticket for unknown socket '$path'\n"
                        if !defined($state->{sockets}->{$path});

                    return {
                        ticket =>
                            PVE::AccessControl::assemble_tunnel_ticket($authuser, "/socket/$path"),
                    };
                },
                'quit' => sub {
                    my ($params) = @_;

                    if ($params->{cleanup}) {
                        if ($state->{cleanup}->{fw}) {
                            PVE::Firewall::remove_vmfw_conf($state->{vmid});
                        }

                        for my $volid (keys $state->{cleanup}->{volumes}->%*) {
                            print "freeing volume '$volid' as part of cleanup\n";
                            eval { PVE::Storage::vdisk_free($state->{storecfg}, $volid) };
                            warn $@ if $@;
                        }

                        PVE::LXC::destroy_lxc_container(
                            $state->{storecfg}, $state->{vmid}, $state->{conf}, undef, 0,
                        );
                    }

                    print "switching to exit-mode, waiting for client to disconnect\n";
                    $state->{exit} = 1;
                    return;
                },
            };

            $run_locked->(sub {
                my $socket_addr = "/run/pve/ct-$state->{vmid}.mtunnel";
                unlink $socket_addr;

                $state->{socket} = IO::Socket::UNIX->new(
                    Type => SOCK_STREAM(),
                    Local => $socket_addr,
                    Listen => 1,
                );

                $state->{socket_uid} = getpwnam('www-data')
                    or die "Failed to resolve user 'www-data' to numeric UID\n";
                chown $state->{socket_uid}, -1, $socket_addr;
            });

            print "mtunnel started\n";

            my $conn = eval {
                PVE::Tools::run_with_timeout(300, sub { $state->{socket}->accept() });
            };
            if ($@) {
                warn "Failed to accept tunnel connection - $@\n";

                warn "Removing tunnel socket..\n";
                unlink $state->{socket};

                warn "Removing temporary VM config..\n";
                $run_locked->(sub {
                    PVE::LXC::destroy_config($state->{vmid});
                });

                die "Exiting mtunnel\n";
            }

            $state->{conn} = $conn;

            my $reply_err = sub {
                my ($msg) = @_;

                my $reply = JSON::encode_json({
                    success => JSON::false,
                    msg => $msg,
                });
                $conn->print("$reply\n");
                $conn->flush();
            };

            my $reply_ok = sub {
                my ($res) = @_;

                $res->{success} = JSON::true;
                my $reply = JSON::encode_json($res);
                $conn->print("$reply\n");
                $conn->flush();
            };

            while (my $line = <$conn>) {
                chomp $line;

                # untaint, we validate below if needed
                ($line) = $line =~ /^(.*)$/;
                my $parsed = eval { JSON::decode_json($line) };
                if ($@) {
                    $reply_err->("failed to parse command - $@");
                    next;
                }

                my $cmd = delete $parsed->{cmd};
                if (!defined($cmd)) {
                    $reply_err->("'cmd' missing");
                } elsif ($state->{exit}) {
                    $reply_err->("tunnel is in exit-mode, processing '$cmd' cmd not possible");
                    next;
                } elsif (my $handler = $cmd_handlers->{$cmd}) {
                    print "received command '$cmd'\n";
                    eval {
                        if (my $props = $cmd_desc->{$cmd}) {
                            my $schema = {
                                type => 'object',
                                properties => $props,
                            };
                            PVE::JSONSchema::validate($parsed, $schema);
                        } else {
                            $parsed = {};
                        }
                        my $res = $run_locked->($handler, $parsed);
                        $reply_ok->($res);
                    };
                    $reply_err->("failed to handle '$cmd' command - $@")
                        if $@;
                } else {
                    $reply_err->("unknown command '$cmd' given");
                }
            }

            if ($state->{exit}) {
                print "mtunnel exited\n";
            } else {
                die "mtunnel exited unexpectedly\n";
            }
        };

        my $ticket =
            PVE::AccessControl::assemble_tunnel_ticket($authuser, "/socket/$socket_addr");
        my $upid = $rpcenv->fork_worker('vzmtunnel', $vmid, $authuser, $realcmd);

        return {
            ticket => $ticket,
            upid => $upid,
            socket => $socket_addr,
        };
    },
});

__PACKAGE__->register_method({
    name => 'mtunnelwebsocket',
    path => '{vmid}/mtunnelwebsocket',
    method => 'GET',
    permissions => {
        description =>
            "You need to pass a ticket valid for the selected socket. Tickets can be created via the mtunnel API call, which will check permissions accordingly.",
        user => 'all', # check inside
    },
    description =>
        'Migration tunnel endpoint for websocket upgrade - only for internal use by VM migration.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            socket => {
                type => "string",
                description => "unix socket to forward to",
            },
            ticket => {
                type => "string",
                description =>
                    "ticket return by initial 'mtunnel' API call, or retrieved via 'ticket' tunnel command",
            },
        },
    },
    returns => {
        type => "object",
        properties => {
            port => { type => 'string', optional => 1 },
            socket => { type => 'string', optional => 1 },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $nodename = PVE::INotify::nodename();
        my $node = extract_param($param, 'node');

        raise_param_exc({
            node => "node needs to be 'localhost' or local hostname '$nodename'" })
            if $node ne 'localhost' && $node ne $nodename;

        my $vmid = $param->{vmid};
        # check VM exists
        PVE::LXC::Config->load_config($vmid);

        my $socket = $param->{socket};
        PVE::AccessControl::verify_tunnel_ticket($param->{ticket}, $authuser,
            "/socket/$socket");

        return { socket => $socket };
    },
});
1;
