package PVE::VZDump::LXC;

use strict;
use warnings;
use File::Path;
use File::Basename;
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::Storage;
use PVE::VZDump;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::Tools;

use base qw (PVE::VZDump::Plugin);

my $default_mount_point = "/mnt/vzsnap0";

my $rsync_vm = sub {
    my ($self, $task, $to, $text, $first) = @_;

    my $disks = $task->{disks};
    my $from = $disks->[0]->{dir} . '/';
    $self->loginfo ("starting $text sync $from to $to");

    my $opts = $self->{vzdump}->{opts};

    my @xattr = $task->{no_xattrs} ? () : ('-X', '-A');

    my $rsync = ['rsync', '--stats', @xattr, '--numeric-ids',
                 '-aH', '--delete', '--no-whole-file',
                 ($first ? '--sparse' : '--inplace'),
                 '--one-file-system', '--relative'];
    push @$rsync, "--bwlimit=$opts->{bwlimit}" if $opts->{bwlimit};
    push @$rsync, map { "--exclude=$_" } @{$self->{vzdump}->{findexcl}};
    push @$rsync, map { "--exclude=$_" } @{$task->{exclude_dirs}};

    my $starttime = time();
    # See the rsync(1) manpage for --relative in conjunction with /./ in paths.
    # This is the only way to have exclude-dirs work together with the
    # --one-file-system option.
    # This way we can pass multiple source paths and tell rsync which directory
    # they're supposed to be relative to.
    # Otherwise with eg. using multiple rsync commands means the --exclude
    # directives need to be modified for every command as they are meant to be
    # relative to the rootdir, while rsync treats them as relative to the
    # source dir.
    foreach my $disk (@$disks) {
	push @$rsync, "$from/.$disk->{mp}";
    }
    $self->cmd([@$rsync, $to]);
    my $delay = time () - $starttime;

    $self->loginfo ("$text sync finished ($delay seconds)");
};

sub new {
    my ($class, $vzdump) = @_;
    
    PVE::VZDump::check_bin('lxc-stop');
    PVE::VZDump::check_bin('lxc-start');
    PVE::VZDump::check_bin('lxc-freeze');
    PVE::VZDump::check_bin('lxc-unfreeze');

    my $self = bless {};

    $self->{vzdump} = $vzdump;
    $self->{storecfg} = PVE::Storage::config();
    
    $self->{vmlist} = PVE::LXC::config_list();

    return $self;
}

sub type {
    return 'lxc';
}

sub vm_status {
    my ($self, $vmid) = @_;

    my $running = PVE::LXC::check_running($vmid) ? 1 : 0;
   
    return wantarray ? ($running, $running ? 'running' : 'stopped') : $running; 
}

my $check_mountpoint_empty = sub {
    my ($mountpoint) = @_;

    die "mount point '$mountpoint' is not a directory\n" if ! -d $mountpoint;

    PVE::Tools::dir_glob_foreach($mountpoint, qr/.*/, sub {
	my $entry = shift;
	return if $entry eq '.' || $entry eq '..';
	die "mount point '$mountpoint' not empty\n";
    });
};

sub prepare {
    my ($self, $task, $vmid, $mode) = @_;

    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::Config->load_config($vmid);
    my $storage_cfg = $self->{storecfg};

    $self->loginfo("CT Name: $conf->{hostname}")
	if defined($conf->{hostname});

    my $running = PVE::LXC::check_running($vmid);

    my $disks = $task->{disks} = [];
    my $exclude_dirs = $task->{exclude_dirs} = [];

    $task->{hostname} = $conf->{'hostname'} || "CT$vmid";

    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    $task->{userns_cmd} = PVE::LXC::userns_command($id_map);

    my $volids = $task->{volids} = [];
    PVE::LXC::Config->foreach_mountpoint($conf, sub {
	my ($name, $data) = @_;
	my $volid = $data->{volume};
	my $mount = $data->{mp};
	my $type = $data->{type};

	return if !$volid || !$mount;

	if (!PVE::LXC::Config->mountpoint_backup_enabled($name, $data)) {
	    push @$exclude_dirs, $mount;
	    $self->loginfo("excluding $type mount point $name ('$mount') from backup");
	    return;
	}

	push @$disks, $data;
	push @$volids, $volid
	    if $type eq 'volume';
    });

    if ($mode eq 'snapshot') {
	if (!PVE::LXC::Config->has_feature('snapshot', $conf, $storage_cfg, undef, undef, 1)) {
	    die "mode failure - some volumes do not support snapshots\n";
	}


	if ($conf->{snapshots} && $conf->{snapshots}->{vzdump}) {
	    $self->loginfo("found old vzdump snapshot (force removal)");
	    PVE::LXC::Config->lock_config($vmid, sub {
		$self->unlock_vm($vmid);
		PVE::LXC::Config->snapshot_delete($vmid, 'vzdump', 1);
		$self->lock_vm($vmid);
	    });
	}

	my $rootdir = $default_mount_point;
	mkpath $rootdir;
	&$check_mountpoint_empty($rootdir);

	# set snapshot_count (freezes CT if snapshot_count > 1)
	$task->{snapshot_count} = scalar(@$volids);
    } elsif ($mode eq 'stop') {
	my $rootdir = $default_mount_point;
	mkpath $rootdir;
	&$check_mountpoint_empty($rootdir);
	PVE::Storage::activate_volumes($storage_cfg, $volids);
    } elsif ($mode eq 'suspend') {
	my $pid = PVE::LXC::find_lxc_pid($vmid);
	foreach my $disk (@$disks) {
	    $disk->{dir} = "/proc/$pid/root$disk->{mp}";
	}
	$task->{snapdir} = $task->{tmpdir};
    } else {
	unlock_vm($self, $vmid);
	die "unknown mode '$mode'\n"; # should not happen
    }

    if ($mode ne 'suspend') {
	# If we perform mount operations, let's unshare the mount namespace
	# to not influence the running host.
	PVE::Tools::unshare(PVE::Tools::CLONE_NEWNS);
	PVE::Tools::run_command(['mount', '--make-rslave', '/']);
    }
}

sub lock_vm {
    my ($self, $vmid) = @_;

    PVE::LXC::Config->set_lock($vmid, 'backup');
}

sub unlock_vm {
    my ($self, $vmid) = @_;

    PVE::LXC::Config->remove_lock($vmid, 'backup')
}

sub snapshot {
    my ($self, $task, $vmid) = @_;

    $self->loginfo("create storage snapshot 'vzdump'");

    # todo: freeze/unfreeze if we have more than one volid
    PVE::LXC::Config->lock_config($vmid, sub {
	$self->unlock_vm($vmid);
	PVE::LXC::Config->snapshot_create($vmid, 'vzdump', 0, "vzdump backup snapshot");
	$self->lock_vm($vmid);
    });
    $task->{cleanup}->{remove_snapshot} = 1;
    
    # reload config
    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::Config->load_config($vmid);
    die "unable to read vzdump snapshot config - internal error"
	if !($conf->{snapshots} && $conf->{snapshots}->{vzdump});

    my $disks = $task->{disks};
    my $volids = $task->{volids};

    my $rootdir = $default_mount_point;
    my $storage_cfg = $self->{storecfg};

    PVE::Storage::activate_volumes($storage_cfg, $volids, 'vzdump');
    foreach my $disk (@$disks) {
	$disk->{dir} = "${rootdir}$disk->{mp}";
	PVE::LXC::mountpoint_mount($disk, $rootdir, $storage_cfg, 'vzdump');
    }

    $task->{snapdir} = $rootdir;
}

sub copy_data_phase1 {
    my ($self, $task) = @_;

    if (my $mntinfo = PVE::VZDump::get_mount_info($task->{snapdir})) {
	if ($mntinfo->{fstype} =~ /^nfs4?/) {
	    $self->loginfo(
		 "temporary directory is on NFS, disabling xattr and acl"
		." support, consider configuring a local tmpdir via"
		." /etc/vzdump.conf\n");
	    $task->{no_xattrs} = 1;
	}
    }

    $self->$rsync_vm($task, $task->{snapdir}, "first", 1);
}

sub copy_data_phase2 {
    my ($self, $task) = @_;

    $self->$rsync_vm($task, $task->{snapdir}, "final", 0);
}

sub stop_vm {
    my ($self, $task, $vmid) = @_;

    my $opts = $self->{vzdump}->{opts};
    my $timeout = $opts->{stopwait} * 60;

    PVE::LXC::vm_stop($vmid, 0, $timeout);
}

sub start_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd(['systemctl', 'start', "pve-container\@$vmid"]);
}

sub suspend_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("lxc-freeze -n $vmid");
}

sub resume_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("lxc-unfreeze -n $vmid");
}

sub assemble {
    my ($self, $task, $vmid) = @_;

    my $tmpdir = $task->{tmpdir};

    mkpath "$tmpdir/etc/vzdump/";

    my $conf = PVE::LXC::Config->load_config($vmid);
    delete $conf->{lock};
    delete $conf->{snapshots};
    delete $conf->{parent};

    PVE::Tools::file_set_contents("$tmpdir/etc/vzdump/pct.conf", PVE::LXC::Config::write_pct_config("/lxc/$vmid.conf", $conf));

    my $firewall ="/etc/pve/firewall/$vmid.fw";
    if (-e  $firewall) {
	PVE::Tools::file_copy($firewall, "$tmpdir/etc/vzdump/pct.fw");
	$task->{fw} = 1;
    }
}

sub archive {
    my ($self, $task, $vmid, $filename, $comp) = @_;

    my $disks = $task->{disks};
    my @sources;

    if ($task->{mode} eq 'stop') {
	my $rootdir = $default_mount_point;
	my $storage_cfg = $self->{storecfg};
	foreach my $disk (@$disks) {
	    $disk->{dir} = "${rootdir}$disk->{mp}";
	    PVE::LXC::mountpoint_mount($disk, $rootdir, $storage_cfg);
	    # add every enabled mountpoint (since we use --one-file-system)
	    # mp already starts with a / so we only need to add the dot
	    push @sources, ".$disk->{mp}";
	}
	$task->{snapdir} = $rootdir;
    } elsif ($task->{mode} eq 'snapshot') {
	# mounting the vzdump snapshots and setting $snapdir is already done,
	# but we need to include all mountpoints here!
	foreach my $disk (@$disks) {
	    push @sources, ".$disk->{mp}";
	}
    } else {
	# the data was rsynced to a temporary location, only use '.' to avoid
	# having mountpoints duplicated
	push @sources, '.';
    }

    my $opts = $self->{vzdump}->{opts};
    my $snapdir = $task->{snapdir};
    my $tmpdir = $task->{tmpdir};

    my $userns_cmd = $task->{userns_cmd};
    my $tar = [@$userns_cmd, 'tar', 'cpf', '-', '--totals',
               @PVE::Storage::Plugin::COMMON_TAR_FLAGS,
               '--one-file-system', '--warning=no-file-ignored'];

    # note: --remove-files does not work because we do not 
    # backup all files (filters). tar complains:
    # Cannot rmdir: Directory not empty
    # we disable this optimization for now
    #if ($snapdir eq $task->{tmpdir} && $snapdir =~ m|^$opts->{dumpdir}/|) {
    #       push @$tar, "--remove-files"; # try to save space
    #}

    # The directory parameter can give an alternative directory as source.
    # the second parameter gives the structure in the tar.
    push @$tar, "--directory=$tmpdir", './etc/vzdump/pct.conf';
    push @$tar, "./etc/vzdump/pct.fw" if $task->{fw};
    push @$tar, "--directory=$snapdir";
    push @$tar, '--no-anchored', '--exclude=lost+found' if $userns_cmd;
    push @$tar, '--anchored';
    push @$tar, map { "--exclude=.$_" } @{$self->{vzdump}->{findexcl}};

    push @$tar, @sources;

    my $cmd = [ $tar ];

    my $bwl = $opts->{bwlimit}*1024; # bandwidth limit for cstream
    push @$cmd, [ 'cstream', '-t', $bwl ] if $opts->{bwlimit};
    push @$cmd, [ split(/\s+/, $comp) ] if $comp;

    if ($opts->{stdout}) {
	$self->cmd($cmd, output => ">&" . fileno($opts->{stdout}));
    } else {
	push @{$cmd->[-1]}, \(">" . PVE::Tools::shellquote($filename));
       $self->cmd($cmd);
    }
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

    my $conf = PVE::LXC::Config->load_config($vmid);

    if ($task->{mode} ne 'suspend') {
	my $rootdir = $default_mount_point;
	my $disks = $task->{disks};
	foreach my $disk (reverse @$disks) {
	    PVE::Tools::run_command(['umount', '-l', '-d', $disk->{dir}]) if $disk->{dir};
	}
    }

    if ($task->{cleanup}->{remove_snapshot}) {
	$self->loginfo("remove vzdump snapshot");
	PVE::LXC::Config->snapshot_delete($vmid, 'vzdump', 0);
    }
}

1;
