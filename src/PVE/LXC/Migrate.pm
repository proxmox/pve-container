package PVE::LXC::Migrate;

use strict;
use warnings;

use File::Basename;
use File::Copy; # fixme: remove

use PVE::Cluster;
use PVE::INotify;
use PVE::Replication;
use PVE::ReplicationConfig;
use PVE::ReplicationState;
use PVE::Storage;
use PVE::Tools;

use PVE::LXC::Config;
use PVE::LXC;

use PVE::AbstractMigrate;
use base qw(PVE::AbstractMigrate);

# compared against remote end's minimum version
our $WS_TUNNEL_VERSION = 2;

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::LXC::Config->lock_config($vmid, $code, @param);
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};
    my $restart= $self->{opts}->{restart};
    my $remote = $self->{opts}->{remote};

    $self->{storecfg} = PVE::Storage::config();

    # test if CT exists
    my $conf = $self->{vmconf} = PVE::LXC::Config->load_config($vmid);

    PVE::LXC::Config->check_lock($conf);

    my $running = 0;
    if (PVE::LXC::check_running($vmid)) {
	die "lxc live migration is currently not implemented\n" if $online;
	die "running container can only be migrated in restart mode" if !$restart;
	$running = 1;
    }
    $self->{was_running} = $running;

    my $storages = {};
    PVE::LXC::Config->foreach_volume_full($conf, { include_unused => 1 }, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my $type = $mountpoint->{type};

	# skip dev/bind mps when shared
	if ($type ne 'volume') {
	    if ($mountpoint->{shared}) {
		return;
	    } else {
		die "cannot migrate local $type mount point '$ms'\n";
	    }
	}

	my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1) if $volid;
	die "can't determine assigned storage for mount point '$ms'\n" if !$storage;

	# check if storage is available on both nodes
	my $scfg = PVE::Storage::storage_check_enabled($self->{storecfg}, $storage);

	my $targetsid = $storage;

	die "content type 'rootdir' is not available on storage '$storage'\n"
	    if !$scfg->{content}->{rootdir};

	if ($scfg->{shared} && !$remote) {
	    # PVE::Storage::activate_storage checks this for non-shared storages
	    my $plugin = PVE::Storage::Plugin->lookup($scfg->{type});
	    warn "Used shared storage '$storage' is not online on source node!\n"
		if !$plugin->check_connection($storage, $scfg);
	} else {
	    # unless in restart mode because we shut the container down
	    die "unable to migrate local mount point '$volid' while CT is running"
		if $running && !$restart;

	    $targetsid = PVE::JSONSchema::map_id($self->{opts}->{storagemap}, $storage);
	}

	if (!$remote) {
	    my $target_scfg = PVE::Storage::storage_check_enabled($self->{storecfg}, $targetsid, $self->{node});

	    die "$volid: content type 'rootdir' is not available on storage '$targetsid'\n"
		if !$target_scfg->{content}->{rootdir};
	}

	$storages->{$targetsid} = 1;
    });

    # todo: test if VM uses local resources

    if ($remote) {
	# test & establish websocket connection
	my $bridges = map_bridges($conf, $self->{opts}->{bridgemap}, 1);

	my $remote = $self->{opts}->{remote};
	my $conn = $remote->{conn};

	my $log = sub {
	    my ($level, $msg) = @_;
	    $self->log($level, $msg);
	};

	my $websocket_url = "https://$conn->{host}:$conn->{port}/api2/json/nodes/$self->{node}/lxc/$remote->{vmid}/mtunnelwebsocket";
	my $url = "/nodes/$self->{node}/lxc/$remote->{vmid}/mtunnel";

	my $tunnel_params = {
	    url => $websocket_url,
	};

	my $storage_list = join(',', keys %$storages);
	my $bridge_list = join(',', keys %$bridges);

	my $req_params = {
	    storages => $storage_list,
	    bridges => $bridge_list,
	};

	my $tunnel = PVE::Tunnel::fork_websocket_tunnel($conn, $url, $req_params, $tunnel_params, $log);
	my $min_version = $tunnel->{version} - $tunnel->{age};
	$self->log('info', "local WS tunnel version: $WS_TUNNEL_VERSION");
	$self->log('info', "remote WS tunnel version: $tunnel->{version}");
	$self->log('info', "minimum required WS tunnel version: $min_version");
	die "Remote tunnel endpoint not compatible, upgrade required\n"
	    if $WS_TUNNEL_VERSION < $min_version;
	 die "Remote tunnel endpoint too old, upgrade required\n"
	    if $WS_TUNNEL_VERSION > $tunnel->{version};

	$self->log('info', "websocket tunnel started\n");
	$self->{tunnel} = $tunnel;
    } else {
	# test ssh connection
	my $cmd = [ @{$self->{rem_ssh}}, '/bin/true' ];
	eval { $self->cmd_quiet($cmd); };
	die "Can't connect to destination address using public key\n" if $@;
    }

    # in restart mode, we shutdown the container before migrating
    if ($restart && $running) {
	my $timeout = $self->{opts}->{timeout} // 180;

	$self->log('info', "shutdown CT $vmid\n");

	PVE::LXC::vm_stop($vmid, 0, $timeout);

	$running = 0;
    }

    return $running;
}

sub phase1 {
    my ($self, $vmid) = @_;

    my $remote = $self->{opts}->{remote};

    $self->log('info', "starting migration of CT $self->{vmid} to node '$self->{node}' ($self->{nodeip})");

    my $conf = $self->{vmconf};
    $conf->{lock} = 'migrate';
    PVE::LXC::Config->write_config($vmid, $conf);

    if ($self->{running}) {
	$self->log('info', "container is running - using online migration");
    }

    $self->{volumes} = []; # list of already migrated volumes
    my $volhash = {}; # 'config', 'snapshot' or 'storage' for local volumes
    my $volhash_errors = {};
    my $abort = 0;

    my $log_error = sub {
	my ($msg, $volid) = @_;

	$volhash_errors->{$volid} = $msg if !defined($volhash_errors->{$volid});
	$abort = 1;
    };

    my $test_volid = sub {
	my ($volid, $snapname) = @_;

	return if !$volid;

	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

	# check if storage is available on source node
	my $scfg = PVE::Storage::storage_check_enabled($self->{storecfg}, $sid);

	my $targetsid = $sid;

	if ($scfg->{shared} && !$remote) {
	    $self->log('info', "volume '$volid' is on shared storage '$sid'")
		if !$snapname;
	    return;
	} else {
	    $targetsid = PVE::JSONSchema::map_id($self->{opts}->{storagemap}, $sid);
	}

	PVE::Storage::storage_check_enabled($self->{storecfg}, $targetsid, $self->{node})
	    if !$remote;

	my $bwlimit = $self->get_bwlimit($sid, $targetsid);

	$volhash->{$volid}->{ref} = defined($snapname) ? 'snapshot' : 'config';
	$volhash->{$volid}->{snapshots} = 1 if defined($snapname);
	$volhash->{$volid}->{targetsid} = $targetsid;
	$volhash->{$volid}->{bwlimit} = $bwlimit;

	my ($path, $owner) = PVE::Storage::path($self->{storecfg}, $volid);

	die "owned by other guest (owner = $owner)\n"
	    if !$owner || ($owner != $self->{vmid});

	if (defined($snapname)) {
	    # we cannot migrate shapshots on local storage
	    # exceptions: 'zfspool', 'btrfs'
	    if ($scfg->{type} eq 'zfspool' || $scfg->{type} eq 'btrfs') {
		return;
	    }
	    die "non-migratable snapshot exists\n";
	}
    };

    my $test_mp = sub {
	my ($ms, $mountpoint, $snapname) = @_;

	my $volid = $mountpoint->{volume};
	# already checked in prepare
	if ($mountpoint->{type} ne 'volume') {
	    $self->log('info', "ignoring shared '$mountpoint->{type}' mount point '$ms' ('$volid')")
		if !$snapname;
	    return;
	}

	eval {
	    &$test_volid($volid, $snapname);

	    die "remote migration with snapshots not supported yet\n"
		if $remote && $snapname;
	};

	&$log_error($@, $volid) if $@;
    };

    # first unused / lost volumes owned by this container
    my @sids = PVE::Storage::storage_ids($self->{storecfg});
    foreach my $storeid (@sids) {
	my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);
	next if $scfg->{shared} && !$remote;
	next if !PVE::Storage::storage_check_enabled($self->{storecfg}, $storeid, undef, 1);

	# get list from PVE::Storage (for unreferenced volumes)
	my $dl = PVE::Storage::vdisk_list($self->{storecfg}, $storeid, $vmid, undef, 'rootdir');

	next if @{$dl->{$storeid}} == 0;

	# check if storage is available on target node
	my $targetsid = PVE::JSONSchema::map_id($self->{opts}->{storagemap}, $storeid);
	if (!$remote) {
	    my $target_scfg = PVE::Storage::storage_check_enabled($self->{storecfg}, $targetsid, $self->{node});

	    die "content type 'rootdir' is not available on storage '$targetsid'\n"
		if !$target_scfg->{content}->{rootdir};
	}

	PVE::Storage::foreach_volid($dl, sub {
	    my ($volid, $sid, $volname) = @_;

	    $volhash->{$volid}->{ref} = 'storage';
	    $volhash->{$volid}->{targetsid} = $targetsid;
	});
    }

    # then all volumes referenced in snapshots
    foreach my $snapname (keys %{$conf->{snapshots}}) {
	&$test_volid($conf->{snapshots}->{$snapname}->{'vmstate'}, 0, undef)
	    if defined($conf->{snapshots}->{$snapname}->{'vmstate'});
	PVE::LXC::Config->foreach_volume($conf->{snapshots}->{$snapname}, $test_mp, $snapname);
    }

    # finally all current volumes
    PVE::LXC::Config->foreach_volume_full($conf, { include_unused => 1 }, $test_mp);

    # additional checks for local storage
    foreach my $volid (keys %$volhash) {
	eval {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg =  PVE::Storage::storage_config($self->{storecfg}, $sid);

	    # TODO move to storage plugin layer?
	    my $migratable_storages = [
		'dir',
		'zfspool',
		'lvmthin',
		'lvm',
		'btrfs',
	    ];
	    if ($remote) {
		push @$migratable_storages, 'cifs';
		push @$migratable_storages, 'nfs';
	    }

	    die "storage type '$scfg->{type}' not supported\n"
		if !grep { $_ eq $scfg->{type} } @$migratable_storages;

	    # image is a linked clone on local storage, se we can't migrate.
	    if (my $basename = (PVE::Storage::parse_volname($self->{storecfg}, $volid))[3]) {
		die "clone of '$basename'";
	    }
	};
	&$log_error($@, $volid) if $@;
    }

    foreach my $volid (sort keys %$volhash) {
	my $ref = $volhash->{$volid}->{ref};
	if ($ref eq 'storage') {
	    $self->log('info', "found local volume '$volid' (via storage)\n");
	} elsif ($ref eq 'config') {
	    $self->log('info', "found local volume '$volid' (in current VM config)\n");
	} elsif ($ref eq 'snapshot') {
	    $self->log('info', "found local volume '$volid' (referenced by snapshot(s))\n");
	} else {
	    $self->log('info', "found local volume '$volid'\n");
	}
    }

    foreach my $volid (sort keys %$volhash_errors) {
	$self->log('warn', "can't migrate local volume '$volid': $volhash_errors->{$volid}");
    }

    if ($abort) {
	die "can't migrate CT - check log\n";
    }

    my $rep_volumes;

    my $rep_cfg = PVE::ReplicationConfig->new();

    if ($remote) {
	die "cannot remote-migrate replicated VM\n"
	    if $rep_cfg->check_for_existing_jobs($vmid, 1);
    } elsif (my $jobcfg = $rep_cfg->find_local_replication_job($vmid, $self->{node})) {
	die "can't live migrate VM with replicated volumes\n" if $self->{running};
	my $start_time = time();
	my $logfunc = sub { my ($msg) = @_;  $self->log('info', $msg); };
	$rep_volumes = PVE::Replication::run_replication(
	    'PVE::LXC::Config', $jobcfg, $start_time, $start_time, $logfunc);
    }

    my $opts = $self->{opts};
    foreach my $volid (keys %$volhash) {
	next if $rep_volumes->{$volid};
	push @{$self->{volumes}}, $volid;

	# JSONSchema and get_bandwidth_limit use kbps - storage_migrate bps
	my $bwlimit = $volhash->{$volid}->{bwlimit};
	$bwlimit = $bwlimit * 1024 if defined($bwlimit);

	my $targetsid = $volhash->{$volid}->{targetsid};

	my $new_volid = eval {
	    if ($remote) {
		my $log = sub {
		    my ($level, $msg) = @_;
		    $self->log($level, $msg);
		};

		return PVE::StorageTunnel::storage_migrate(
		    $self->{tunnel},
		    $self->{storecfg},
		    $volid,
		    $self->{vmid},
		    $remote->{vmid},
		    $volhash->{$volid},
		    $log,
		);
	    } else {
		my $storage_migrate_opts = {
		    'ratelimit_bps' => $bwlimit,
		    'insecure' => $opts->{migration_type} eq 'insecure',
		    'with_snapshots' => $volhash->{$volid}->{snapshots},
		    'allow_rename' => 1,
		};

		my $logfunc = sub { $self->log('info', $_[0]); };
		return PVE::Storage::storage_migrate(
		    $self->{storecfg},
		    $volid,
		    $self->{ssh_info},
		    $targetsid,
		    $storage_migrate_opts,
		    $logfunc,
		);
	    }
	};

	if (my $err = $@) {
	    die "storage migration for '$volid' to storage '$targetsid' failed - $err\n";
	}

	$self->{volume_map}->{$volid} = $new_volid;
	$self->log('info', "volume '$volid' is '$new_volid' on the target\n");

	eval { PVE::Storage::deactivate_volumes($self->{storecfg}, [$volid]); };
	if (my $err = $@) {
	    $self->log('warn', $err);
	}
    }

    if ($self->{running}) {
	die "implement me";
    }

    # make sure everything on (shared) storage is unmounted
    # Note: we must be 100% sure, else we get data corruption because
    # non-shared file system could be mounted twice (on shared storage)

    PVE::LXC::umount_all($vmid, $self->{storecfg}, $conf);

    #to be sure there are no active volumes
    my $vollist = PVE::LXC::Config->get_vm_volumes($conf);
    PVE::Storage::deactivate_volumes($self->{storecfg}, $vollist);

    if ($remote) {
	my $remote_conf = PVE::LXC::Config->load_config($vmid);
	PVE::LXC::Config->update_volume_ids($remote_conf, $self->{volume_map});

	my $bridges = map_bridges($remote_conf, $self->{opts}->{bridgemap});
	for my $target (keys $bridges->%*) {
	    for my $nic (keys $bridges->{$target}->%*) {
		$self->log('info', "mapped: $nic from $bridges->{$target}->{$nic} to $target");
	    }
	}
	my $conf_str = PVE::LXC::Config::write_pct_config("remote", $remote_conf);

	# TODO expose in PVE::Firewall?
	my $vm_fw_conf_path = "/etc/pve/firewall/$vmid.fw";
	my $fw_conf_str;
	$fw_conf_str = PVE::Tools::file_get_contents($vm_fw_conf_path)
	    if -e $vm_fw_conf_path;
	my $params = {
	    conf => $conf_str,
	    'firewall-config' => $fw_conf_str,
	};

	PVE::Tunnel::write_tunnel($self->{tunnel}, 10, 'config', $params);
    } else {
	# transfer replication state before moving config
	$self->transfer_replication_state() if $rep_volumes;
	PVE::LXC::Config->update_volume_ids($conf, $self->{volume_map});
	PVE::LXC::Config->write_config($vmid, $conf);
	PVE::LXC::Config->move_config_to_node($vmid, $self->{node});
	$self->switch_replication_job_target() if $rep_volumes;
    }
    $self->{conf_migrated} = 1;
}

sub phase1_cleanup {
    my ($self, $vmid, $err) = @_;

    $self->log('info', "aborting phase 1 - cleanup resources");

    if ($self->{volumes}) {
	foreach my $volid (@{$self->{volumes}}) {
	    if (my $mapped_volume = $self->{volume_map}->{$volid}) {
		$volid = $mapped_volume;
	    }
	    $self->log('err', "found stale volume copy '$volid' on node '$self->{node}'");
	    # fixme: try to remove ?
	}
    }

    if ($self->{opts}->{remote}) {
	# cleans up remote volumes
	PVE::Tunnel::finish_tunnel($self->{tunnel}, 1);
	delete $self->{tunnel};
    }
}

sub phase3 {
    my ($self, $vmid) = @_;

    my $volids = $self->{volumes};

    # handled below in final_cleanup
    return if $self->{opts}->{remote};

    # destroy local copies
    foreach my $volid (@$volids) {
	eval { PVE::Storage::vdisk_free($self->{storecfg}, $volid); };
	if (my $err = $@) {
	    $self->log('err', "removing local copy of '$volid' failed - $err");
	    $self->{errors} = 1;
	    last if $err =~ /^interrupted by signal$/;
	}
    }
}

sub final_cleanup {
    my ($self, $vmid) = @_;

    $self->log('info', "start final cleanup");

    if (!$self->{conf_migrated}) {
	eval { PVE::LXC::Config->remove_lock($vmid, 'migrate'); };
	if (my $err = $@) {
	    $self->log('err', $err);
	}
	# in restart mode, we start the container on the source node on migration error
	if ($self->{opts}->{restart} && $self->{was_running}) {
	    $self->log('info', "start container on source node");
	    my $skiplock = 1;
	    PVE::LXC::vm_start($vmid, $self->{vmconf}, $skiplock);
	}
    } elsif ($self->{opts}->{remote}) {
	eval { PVE::Tunnel::write_tunnel($self->{tunnel}, 10, 'unlock') };
	$self->log('err', "Failed to clear migrate lock - $@\n") if $@;

	if ($self->{opts}->{restart} && $self->{was_running}) {
	    $self->log('info', "start container on target node");
	    PVE::Tunnel::write_tunnel($self->{tunnel}, 60, 'start');
	}
	if ($self->{opts}->{delete}) {
	    PVE::LXC::destroy_lxc_container(
		PVE::Storage::config(),
		$vmid,
		PVE::LXC::Config->load_config($vmid),
		undef,
		0,
	    );
	}
	PVE::Tunnel::finish_tunnel($self->{tunnel});
    } else {
	my $cmd = [ @{$self->{rem_ssh}}, 'pct', 'unlock', $vmid ];
	$self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");

	# in restart mode, we start the container on the target node after migration
	if ($self->{opts}->{restart} && $self->{was_running}) {
	    $self->log('info', "start container on target node");
	    my $cmd = [ @{$self->{rem_ssh}}, 'pct', 'start', $vmid];
	    $self->cmd($cmd);
	}
    }
}

sub map_bridges {
    my ($conf, $map, $scan_only) = @_;

    my $bridges = {};

    foreach my $opt (keys %$conf) {
	next if $opt !~ m/^net\d+$/;

	next if !$conf->{$opt};
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$opt});
	next if !$d || !$d->{bridge};

	my $target_bridge = PVE::JSONSchema::map_id($map, $d->{bridge});
	$bridges->{$target_bridge}->{$opt} = $d->{bridge};

	next if $scan_only;

	$d->{bridge} = $target_bridge;
	$conf->{$opt} = PVE::LXC::Config->print_lxc_network($d);
    }

    return $bridges;
}

1;
