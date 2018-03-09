package PVE::LXC::Migrate;

use strict;
use warnings;
use PVE::AbstractMigrate;
use File::Basename;
use File::Copy; # fixme: remove
use PVE::Tools;
use PVE::INotify;
use PVE::Cluster;
use PVE::Storage;
use PVE::LXC::Config;
use PVE::LXC;
use PVE::ReplicationConfig;
use PVE::ReplicationState;
use PVE::Replication;

use base qw(PVE::AbstractMigrate);

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::LXC::Config->lock_config($vmid, $code, @param);
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};
    my $restart= $self->{opts}->{restart};

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

    my $force = $self->{opts}->{force} // 0;
    my $need_activate = [];

    PVE::LXC::Config->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my $type = $mountpoint->{type};

	# skip dev/bind mps when forced / shared
	if ($type ne 'volume') {
	    if ($force) {
		warn "-force is deprecated, please use the 'shared' property on individual non-volume mount points instead!\n";
		return;
	    }
	    if ($mountpoint->{shared}) {
		return;
	    } else {
		die "cannot migrate local $type mount point '$ms'\n";
	    }
	}

	my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1) if $volid;
	die "can't determine assigned storage for mount point '$ms'\n" if !$storage;

	# check if storage is available on both nodes
	my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $storage);
	PVE::Storage::storage_check_node($self->{storecfg}, $storage, $self->{node});


	if ($scfg->{shared}) {
	    # PVE::Storage::activate_storage checks this for non-shared storages
	    my $plugin = PVE::Storage::Plugin->lookup($scfg->{type});
	    warn "Used shared storage '$storage' is not online on source node!\n"
		if !$plugin->check_connection($storage, $scfg);
	} else {
	    # only activate if not shared
	    push @$need_activate, $volid;

	    # unless in restart mode because we shut the container down
	    die "unable to migrate local mount point '$volid' while CT is running"
		if $running && !$restart;
	}

    });

    PVE::Storage::activate_volumes($self->{storecfg}, $need_activate);

    # todo: test if VM uses local resources

    # test ssh connection
    my $cmd = [ @{$self->{rem_ssh}}, '/bin/true' ];
    eval { $self->cmd_quiet($cmd); };
    die "Can't connect to destination address using public key\n" if $@;

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

	# check if storage is available on both nodes
	my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $sid);
	PVE::Storage::storage_check_node($self->{storecfg}, $sid, $self->{node});

	if ($scfg->{shared}) {
	    $self->log('info', "volume '$volid' is on shared storage '$sid'")
		if !$snapname;
	    return;
	}

	$volhash->{$volid}->{ref} = defined($snapname) ? 'snapshot' : 'config';
	$volhash->{$volid}->{snapshots} = defined($snapname);

	my ($path, $owner) = PVE::Storage::path($self->{storecfg}, $volid);

	die "owned by other guest (owner = $owner)\n"
	    if !$owner || ($owner != $self->{vmid});

	if (defined($snapname)) {
	    # we cannot migrate shapshots on local storage
	    # exceptions: 'zfspool'
	    if (($scfg->{type} eq 'zfspool')) {
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
	};

	&$log_error($@, $volid) if $@;
    };

    # first unused / lost volumes owned by this container
    my @sids = PVE::Storage::storage_ids($self->{storecfg});
    foreach my $storeid (@sids) {
	my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);
	next if $scfg->{shared};
	next if !PVE::Storage::storage_check_enabled($self->{storecfg}, $storeid, undef, 1);

	# get list from PVE::Storage (for unused volumes)
	my $dl = PVE::Storage::vdisk_list($self->{storecfg}, $storeid, $vmid);

	next if @{$dl->{$storeid}} == 0;

	# check if storage is available on target node
	PVE::Storage::storage_check_node($self->{storecfg}, $storeid, $self->{node});

	PVE::Storage::foreach_volid($dl, sub {
	    my ($volid, $sid, $volname) = @_;

	    $volhash->{$volid}->{ref} = 'storage';
	});
    }

    # then all volumes referenced in snapshots
    foreach my $snapname (keys %{$conf->{snapshots}}) {
	&$test_volid($conf->{snapshots}->{$snapname}->{'vmstate'}, 0, undef)
	    if defined($conf->{snapshots}->{$snapname}->{'vmstate'});
	PVE::LXC::Config->foreach_mountpoint($conf->{snapshots}->{$snapname}, $test_mp, $snapname);
    }

    # finally all currently used volumes
    PVE::LXC::Config->foreach_mountpoint($conf, $test_mp);


    # additional checks for local storage
    foreach my $volid (keys %$volhash) {
	eval {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg =  PVE::Storage::storage_config($self->{storecfg}, $sid);

	    my $migratable = ($scfg->{type} eq 'dir') || ($scfg->{type} eq 'zfspool') ||
		($scfg->{type} eq 'lvmthin') || ($scfg->{type} eq 'lvm');

	    die "storage type '$scfg->{type}' not supported\n"
		if !$migratable;

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

    if (my $jobcfg = $rep_cfg->find_local_replication_job($vmid, $self->{node})) {
	die "can't live migrate VM with replicated volumes\n" if $self->{running};
	my $start_time = time();
	my $logfunc = sub { my ($msg) = @_;  $self->log('info', $msg); };
	$rep_volumes = PVE::Replication::run_replication(
	    'PVE::LXC::Config', $jobcfg, $start_time, $start_time, $logfunc);
    }

    my $insecure = $self->{opts}->{migration_type} eq 'insecure';
    foreach my $volid (keys %$volhash) {
	next if $rep_volumes->{$volid};
	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	push @{$self->{volumes}}, $volid;
	my $with_snapshots = $volhash->{$volid}->{snapshots};
	PVE::Storage::storage_migrate($self->{storecfg}, $volid, $self->{ssh_info}, $sid, undef, undef, undef, undef, $insecure, $with_snapshots);
    }

    my $conffile = PVE::LXC::Config->config_file($vmid);
    my $newconffile = PVE::LXC::Config->config_file($vmid, $self->{node});

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

   # transfer replication state before move config
    $self->transfer_replication_state() if $rep_volumes;

    # move config
    die "Failed to move config to node '$self->{node}' - rename failed: $!\n"
	if !rename($conffile, $newconffile);

    $self->{conf_migrated} = 1;

    $self->switch_replication_job_target() if $rep_volumes;
}

sub phase1_cleanup {
    my ($self, $vmid, $err) = @_;

    $self->log('info', "aborting phase 1 - cleanup resources");

    if ($self->{volumes}) {
	foreach my $volid (@{$self->{volumes}}) {
	    $self->log('err', "found stale volume copy '$volid' on node '$self->{node}'");
	    # fixme: try to remove ?
	}
    }
}

sub phase3 {
    my ($self, $vmid) = @_;

    my $volids = $self->{volumes};

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
	# in restart mode, we start the container on the source node
	# on migration error
	if ($self->{opts}->{restart} && $self->{was_running}) {
	    $self->log('info', "start container on source node");
	    my $skiplock = 1;
	    PVE::LXC::vm_start($vmid, $self->{vmconf}, $skiplock);
	}
    } else {
	my $cmd = [ @{$self->{rem_ssh}}, 'pct', 'unlock', $vmid ];
	$self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");

	# in restart mode, we start the container on the target node
	# after migration
	if ($self->{opts}->{restart} && $self->{was_running}) {
	    $self->log('info', "start container on target node");
	    my $cmd = [ @{$self->{rem_ssh}}, 'pct', 'start', $vmid];
	    $self->cmd($cmd);
	}
    }

}

1;
