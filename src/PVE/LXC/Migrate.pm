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
use PVE::LXC;

use base qw(PVE::AbstractMigrate);

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::LXC::lock_config($vmid, $code, @param);
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};

    $self->{storecfg} = PVE::Storage::config();

    # test is VM exist
    my $conf = $self->{vmconf} = PVE::LXC::load_config($vmid);

    PVE::LXC::check_lock($conf);

    my $running = 0;
    if (PVE::LXC::check_running($vmid)) {
	die "lxc live migration is currently not implemented\n";

	die "cant migrate running container without --online\n" if !$online;
	$running = 1;
    }

    PVE::LXC::foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1) if $volid;
	die "can't determine assigned storage for mountpoint '$ms'\n" if !$storage;

	# check if storage is available on both nodes
	my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $storage);
	PVE::Storage::storage_check_node($self->{storecfg}, $storage, $self->{node});

	die "unable to migrate local mountpoint '$volid' while CT is running"
	    if !$scfg->{shared} && $running;

    });

    my $volid_list = PVE::LXC::get_vm_volumes($conf);
    PVE::Storage::activate_volumes($self->{storecfg}, $volid_list);

    # todo: test if VM uses local resources

    # test ssh connection
    my $cmd = [ @{$self->{rem_ssh}}, '/bin/true' ];
    eval { $self->cmd_quiet($cmd); };
    die "Can't connect to destination address using public key\n" if $@;

    return $running;
}

sub phase1 {
    my ($self, $vmid) = @_;

    $self->log('info', "starting migration of CT $self->{vmid} to node '$self->{node}' ($self->{nodeip})");

    my $conf = $self->{vmconf};
    $conf->{lock} = 'migrate';
    PVE::LXC::write_config($vmid, $conf);

    if ($self->{running}) {
	$self->log('info', "container is running - using online migration");
    }

    $self->{volumes} = [];

    PVE::LXC::foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my ($storage, $volname) = PVE::Storage::parse_volume_id($volid);
	my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $storage);

	if (!$scfg->{shared}) {

	    $self->log('info', "copy mointpoint '$ms' ($volid) to node ' $self->{node}'");
	    PVE::Storage::storage_migrate($self->{storecfg}, $volid, $self->{nodeip}, $storage);
	    push @{$self->{volumes}}, $volid;
	} else {
	    $self->log('info', "mointpoint '$ms' is on shared storage '$storage'");
	}
    });

    my $conffile = PVE::LXC::config_file($vmid);
    my $newconffile = PVE::LXC::config_file($vmid, $self->{node});

    if ($self->{running}) {
	die "implement me";
    }

    # make sure everything on (shared) storage is unmounted
    # Note: we must be 100% sure, else we get data corruption because
    # non-shared file system could be mounted twice (on shared storage)

    PVE::LXC::umount_all($vmid, $self->{storecfg}, $conf);

    #to be sure there are no active volumes
    my $vollist = PVE::LXC::get_vm_volumes($conf);
    PVE::Storage::deactivate_volumes($self->{storecfg}, $vollist);

    # move config
    die "Failed to move config to node '$self->{node}' - rename failed: $!\n"
	if !rename($conffile, $newconffile);

    $self->{conf_migrated} = 1;
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
	my $conf = $self->{vmconf};
	delete $conf->{lock};

	eval { PVE::LXC::write_config($vmid, $conf); };
	if (my $err = $@) {
	    $self->log('err', $err);
	}
    } else {
	my $cmd = [ @{$self->{rem_ssh}}, 'pct', 'unlock', $vmid ];
	$self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");	
    }
}

1;
