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
use PVE::Tools;

use base qw (PVE::VZDump::Plugin);

my $default_mount_point = "/mnt/vzsnap0";

my $rsync_vm = sub {
    my ($self, $task, $to, $text) = @_;

    my $disks = $task->{disks};
    my $from = $disks->[0]->{dir} . '/';
    $self->loginfo ("starting $text sync $from to $to");

    my $opts = $self->{vzdump}->{opts};

    my @xattr = $task->{no_xattrs} ? () : ('-X', '-A');

    my $rsync = ['rsync', '--stats', @xattr, '--numeric-ids',
                 '-aH', '--delete', '--no-whole-file', '--inplace',
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

    die "mountpoint '$mountpoint' is not a directory\n" if ! -d $mountpoint;

    PVE::Tools::dir_glob_foreach($mountpoint, qr/.*/, sub {
	my $entry = shift;
	return if $entry eq '.' || $entry eq '..';
	die "mountpoint '$mountpoint' not empty\n";
    });
};

sub prepare {
    my ($self, $task, $vmid, $mode) = @_;

    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::load_config($vmid);
    my $storage_cfg = $self->{storecfg};

    my $running = PVE::LXC::check_running($vmid);

    my $disks = $task->{disks} = [];
    my $exclude_dirs = $task->{exclude_dirs} = [];

    $task->{hostname} = $conf->{'hostname'} || "CT$vmid";

    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    $task->{userns_cmd} = PVE::LXC::userns_command($id_map);

    PVE::LXC::foreach_mountpoint($conf, sub {
	my ($name, $data) = @_;
	my $volid = $data->{volume};
	my $mount = $data->{mp};
	my $type = $data->{type};

	return if !$volid || !$mount;

	if ($name ne 'rootfs' && !$data->{backup}) {
	    push @$exclude_dirs, $mount;
	    return;
	}

	push @$disks, $data;
    });
    my $volid_list = [map { $_->{volume} } @$disks];

    if ($mode eq 'snapshot') {
	if (!PVE::LXC::has_feature('snapshot', $conf, $storage_cfg)) {
	    die "mode failure - some volumes does not support snapshots\n";
	}

	if ($conf->{snapshots} && $conf->{snapshots}->{vzdump}) {
	    $self->loginfo("found old vzdump snapshot (force removal)");
	    PVE::LXC::snapshot_delete($vmid, 'vzdump', 1);
	}

	my $rootdir = $default_mount_point;
	mkpath $rootdir;
	&$check_mountpoint_empty($rootdir);

	# set snapshot_count (freezes CT it snapshot_count > 1)
	$task->{snapshot_count} = scalar(@$volid_list);
    } elsif ($mode eq 'stop') {
	my $rootdir = $default_mount_point;
	mkpath $rootdir;
	&$check_mountpoint_empty($rootdir);
	PVE::Storage::activate_volumes($storage_cfg, $volid_list);
    } elsif ($mode eq 'suspend') {
	my $pid = PVE::LXC::find_lxc_pid($vmid);
	foreach my $disk (@$disks) {
	    $disk->{dir} = "/proc/$pid/root$disk->{mp}";
	}
	$task->{snapdir} = $task->{tmpdir};
    } else {
	die "unknown mode '$mode'\n"; # should not happen
    }

    if ($mode ne 'suspend') {
	# If we preform mount operations, let's unshare the mount namespace
	# to not influence the running host.
	PVE::Tools::unshare(PVE::Tools::CLONE_NEWNS);
	PVE::Tools::run_command(['mount', '--make-rprivate', '/']);
    }
}

sub lock_vm {
    my ($self, $vmid) = @_;

    PVE::LXC::lock_aquire($vmid);
}

sub unlock_vm {
    my ($self, $vmid) = @_;

    PVE::LXC::lock_release($vmid);
}

sub snapshot {
    my ($self, $task, $vmid) = @_;

    $self->loginfo("create storage snapshot snapshot");

    # todo: freeze/unfreeze if we have more than one volid
    PVE::LXC::snapshot_create($vmid, 'vzdump', "vzdump backup snapshot");
    $task->{cleanup}->{remove_snapshot} = 1;
    
    # reload config
    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::load_config($vmid);
    die "unable to read vzdump shanpshot config - internal error"
	if !($conf->{snapshots} && $conf->{snapshots}->{vzdump});

    my $disks = $task->{disks};
    my $volid_list = [map { $_->{volume} } @$disks];

    my $rootdir = $default_mount_point;
    my $storage_cfg = $self->{storecfg};

    PVE::Storage::activate_volumes($storage_cfg, $volid_list, 'vzdump');
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
	    warn "temporary directory is on NFS, disabling xattr and acl support"
	    . ", consider configuring a local tmpdir via /etc/vzdump.conf\n";
	    $task->{no_xattrs} = 1;
	}
    }

    $self->$rsync_vm($task, $task->{snapdir}, "first");
}

sub copy_data_phase2 {
    my ($self, $task) = @_;

    $self->$rsync_vm($task, $task->{snapdir}, "final");
}

sub stop_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd("lxc-stop -n $vmid");
}

sub start_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("lxc-start -n $vmid");
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

    my $conf = PVE::LXC::load_config($vmid);
    delete $conf->{snapshots};
    delete $conf->{'pve.parent'};

    PVE::Tools::file_set_contents("$tmpdir/etc/vzdump/pct.conf", PVE::LXC::write_pct_config("/lxc/$vmid.conf", $conf));

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
               @$PVE::LXC::COMMON_TAR_FLAGS,
               '--one-file-system', '--warning=no-file-ignored'];

    # note: --remove-files does not work because we do not 
    # backup all files (filters). tar complains:
    # Cannot rmdir: Directory not empty
    # we we disable this optimization for now
    #if ($snapdir eq $task->{tmpdir} && $snapdir =~ m|^$opts->{dumpdir}/|) {
    #       push @$tar, "--remove-files"; # try to save space
    #}

    # The directory parameter can give a alternative directory as source.
    # the second parameter gives the structure in the tar.
    push @$tar, "--directory=$tmpdir", './etc/vzdump/pct.conf';
    push @$tar, "./etc/vzdump/pct.fw" if $task->{fw};
    push @$tar, "--directory=$snapdir";
    push @$tar, '--anchored';
    push @$tar, map { "--exclude=.$_" } @{$self->{vzdump}->{findexcl}};

    push @$tar, @sources;

    my $cmd = [ $tar ];

    my $bwl = $opts->{bwlimit}*1024; # bandwidth limit for cstream
    push @$cmd, [ 'cstream', '-t', $bwl ] if $opts->{bwlimit};
    push @$cmd, [ $comp ] if $comp;

    if ($opts->{stdout}) {
	push @{$cmd->[-1]}, \(">&" . fileno($opts->{stdout}));
    } else {
	push @{$cmd->[-1]}, \(">" . PVE::Tools::shellquote($filename));
    }
    $self->cmd($cmd);
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

    my $conf = PVE::LXC::load_config($vmid);

    if ($task->{mode} ne 'suspend') {
	my $rootdir = $default_mount_point;
	my $disks = $task->{disks};
	foreach my $disk (reverse @$disks) {
	    PVE::Tools::run_command(['umount', '-l', '-d', $disk->{dir}]) if $disk->{dir};
	}
    }

    if ($task->{cleanup}->{remove_snapshot}) {
	$self->loginfo("remove vzdump snapshot");
	PVE::LXC::snapshot_delete($vmid, 'vzdump', 0);
    }
}

1;
