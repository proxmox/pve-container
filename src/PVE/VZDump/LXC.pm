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
    my ($self, $task, $from, $to, $text) = @_;

    $self->loginfo ("starting $text sync $from to $to");

    my $starttime = time();

    my $opts = $self->{vzdump}->{opts};

    my $rsyncopts = "--stats -x -X --numeric-ids";

    $rsyncopts .= " --bwlimit=$opts->{bwlimit}" if $opts->{bwlimit};

    $self->cmd ("rsync $rsyncopts -aH --delete --no-whole-file --inplace '$from' '$to'");

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

    PVE::LXC::foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	return if $ms eq 'rootfs';
	# TODO: implement support for mountpoints
	die "unable to backup mountpoint '$ms' - feature not implemented\n";
    });

    my $running = PVE::LXC::check_running($vmid);

    my $diskinfo = $task->{diskinfo} = {};

    $task->{hostname} = $conf->{'hostname'} || "CT$vmid";

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    $diskinfo->{volid} = $rootinfo->{volume};

    die "missing root volid (no volid)\n" if !$diskinfo->{volid};

    # fixme: when do we deactivate ??
    PVE::Storage::activate_volumes($self->{storecfg}, [$diskinfo->{volid}]);

    if ($mode eq 'snapshot') {

	if (!PVE::LXC::has_feature('snapshot', $conf, $self->{storecfg})) {
	    die "mode failure - some volumes does not support snapshots\n";
	}

	if ($conf->{snapshots} && $conf->{snapshots}->{vzdump}) {
	    $self->loginfo("found old vzdump snapshot (force removal)");
	    PVE::LXC::snapshot_delete($vmid, 'vzdump', 0);
	}

	my $mountpoint = $default_mount_point;
	mkpath $mountpoint;
	&$check_mountpoint_empty($mountpoint);

	# set snapshot_count (freezes CT it snapshot_count > 1)
	my $volid_list = PVE::LXC::get_vm_volumes($conf);
	$task->{snapshot_count} = scalar(@$volid_list);
	
    } elsif ($mode eq 'stop') {
	my $mountpoint = $default_mount_point;
	mkpath $mountpoint;
	&$check_mountpoint_empty($mountpoint);
    } elsif ($mode eq 'suspend') {
	my $pid = PVE::LXC::find_lxc_pid($vmid);
	$diskinfo->{dir} = "/proc/$pid/root";
	$task->{snapdir} = $task->{tmpdir};
    } else {
	die "unknown mode '$mode'\n"; # should not happen
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

    my $diskinfo = $task->{diskinfo};

    $self->loginfo("create storage snapshot snapshot");

    # todo: freeze/unfreeze if we have more than one volid
    PVE::LXC::snapshot_create($vmid, 'vzdump', "vzdump backup snapshot");
    $task->{cleanup}->{remove_snapshot} = 1;
    
    # reload config
    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::load_config($vmid);
    die "unable to read vzdump shanpshot config - internal error"
	if !($conf->{snapshots} && $conf->{snapshots}->{vzdump});

    # my $snapconf = $conf->{snapshots}->{vzdump};
    # my $volid_list = PVE::LXC::get_vm_volumes($snapconf);
    my $volid_list = [$diskinfo->{volid}];

    my $mountpoint = $default_mount_point;
	
    my $mp = { volume => $diskinfo->{volid}, mp => "/" };
    PVE::LXC::mountpoint_mount($mp, $mountpoint, $self->{storecfg}, 'vzdump');
 
    $diskinfo->{dir} = $diskinfo->{mountpoint} = $mountpoint;
    $task->{snapdir} = $diskinfo->{dir};
}

sub copy_data_phase1 {
    my ($self, $task) = @_;

    $self->$rsync_vm($task, "$task->{diskinfo}->{dir}/", $task->{snapdir}, "first");
}

sub copy_data_phase2 {
    my ($self, $task) = @_;

    $self->$rsync_vm ($task, "$task->{diskinfo}->{dir}/", $task->{snapdir}, "final");
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
}

sub archive {
    my ($self, $task, $vmid, $filename, $comp) = @_;

    if ($task->{mode} eq 'stop') {
	my $mountpoint = $default_mount_point;
	my $diskinfo = $task->{diskinfo};

	my $volid_list = [$diskinfo->{volid}];
	my $mp = { volume => $diskinfo->{volid}, mp => "/" };

	$self->loginfo("mounting container root at '$mountpoint'");
	PVE::LXC::mountpoint_mount($mp, $mountpoint, $self->{storecfg});

	$diskinfo->{dir} = $diskinfo->{mountpoint} = $mountpoint;
	$task->{snapdir} = $diskinfo->{dir};
    }

    my $findexcl = $self->{vzdump}->{findexcl};
    push @$findexcl, "'('", '-path', "./etc/vzdump", "-prune", "')'", '-o';

    my $findargs = join (' ', @$findexcl) . ' -print0';
    my $opts = $self->{vzdump}->{opts};

    my $srcdir = $task->{diskinfo}->{dir};
    my $snapdir = $task->{snapdir};
    my $tmpdir = $task->{tmpdir};

    my $taropts = "--totals --sparse --numeric-owner --no-recursion --xattrs --one-file-system";

    # note: --remove-files does not work because we do not 
    # backup all files (filters). tar complains:
    # Cannot rmdir: Directory not empty
    # we we disable this optimization for now
    #if ($snapdir eq $task->{tmpdir} && $snapdir =~ m|^$opts->{dumpdir}/|) {
    #       $taropts .= " --remove-files"; # try to save space
    #}

    my $cmd = "(";

    $cmd .= "cd $snapdir;find . $findargs|sed 's/\\\\/\\\\\\\\/g'|";
    $cmd .= "tar cpf - $taropts ";
    # The directory parameter can give a alternative directory as source.
    # the second parameter gives the structure in the tar.
    $cmd .= "--directory=$tmpdir ./etc/vzdump/pct.conf ";
    $cmd .= "--directory=$snapdir --null -T -";

    my $bwl = $opts->{bwlimit}*1024; # bandwidth limit for cstream
    $cmd .= "|cstream -t $bwl" if $opts->{bwlimit};
    $cmd .= "|$comp" if $comp;

    $cmd .= ")";

    if ($opts->{stdout}) {
	$self->cmd ($cmd, output => ">&" . fileno($opts->{stdout}));
    } else {
	$self->cmd ("$cmd >$filename");
    }
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

    my $diskinfo = $task->{diskinfo};

    if (my $mountpoint = $diskinfo->{mountpoint}) {
	PVE::Tools::run_command(['umount', '-l', '-d', $mountpoint]);
    };

    if ($task->{cleanup}->{remove_snapshot}) {
	$self->loginfo("remove vzdump snapshot");
	PVE::LXC::snapshot_delete($vmid, 'vzdump', 0);
    }
}

1;
