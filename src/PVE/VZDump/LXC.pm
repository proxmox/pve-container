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

my $check_mointpoint_empty = sub {
    my ($mountpoint) = @_;

    PVE::Tools::dir_glob_foreach($mountpoint, qr/.*/, sub {
	my $entry = shift;
	return if $entry eq '.' || $entry eq '..';
	die "mointpoint '$mountpoint' not empty\n";
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

    my $diskinfo = {};
    $task->{diskinfo} = $diskinfo;

    $task->{hostname} = $conf->{'hostname'} || "CT$vmid";

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    my $volid = $rootinfo->{volume};

    die "missing root volid (no volid)\n" if !$volid;

    # fixme: when do we deactivate ??
    PVE::Storage::activate_volumes($self->{storecfg}, [$volid]);

    if ($mode eq 'snapshot') {

	die "mode failure - storage does not support snapshots\n"
	    if !PVE::Storage::volume_has_feature($self->{storecfg}, 'snapshot', $volid);
	
	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

	my $scfg = PVE::Storage::storage_config($self->{storecfg}, $sid);

	# we only handle well known types for now, because the storage
	# library dos not handle mount/unmount of snapshots

	if ($scfg->{type} ne 'zfs') {
	    $diskinfo->{mountpoint} = "/mnt/vzsnap0";
	    &$check_mointpoint_empty($diskinfo->{mountpoint});
	} else {
	    die "mode failure - storage does not support snapshot mount\n"
	}
	
	PVE::Storage::volume_snapshot($self->{storecfg}, $volid, '__vzdump__');
	$task->{cleanup}->{snap_volid} = $volid;
	
	die "implement me";
	
    } elsif ($mode eq 'stop') {
	my $mountpoint = "/mnt/vzsnap0";

	&$check_mointpoint_empty($mountpoint);

	my $volid_list = [$volid];
	$task->{cleanup}->{dettach_loops} = $volid_list;
	my $loopdevs = PVE::LXC::attach_loops($self->{storecfg}, $volid_list);
	my $mp = { volume => $volid, mp => "/" };
	PVE::LXC::mountpoint_mount($mp, $mountpoint, $self->{storecfg}, $loopdevs);
	$diskinfo->{dir} = $diskinfo->{mountpoint} = $mountpoint;
	$task->{snapdir} = $diskinfo->{dir};
    } elsif ($mode eq 'suspend') {
	my $tasks_fn = "/sys/fs/cgroup/cpu/lxc/$vmid/tasks";
	my $init_pid = PVE::Tools::file_read_firstline($tasks_fn);
	if ($init_pid =~ m/^(\d+)$/) {
	    $diskinfo->{dir} = "/proc/$1/root";
	} else {
	    die "unable to find container init task\n";
	}
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

    my $di = $task->{diskinfo};

    if (my $mountpoint = $di->{mountpoint}) {
	PVE::Tools::run_command(['umount', '-l', '-d', $mountpoint]);
    };

    if (my $volid_list = $task->{cleanup}->{dettach_loops}) {
	PVE::LXC::dettach_loops($self->{storecfg}, $volid_list);
    }

    if (my $volid = $task->{cleanup}->{snap_volid}) {
	eval { PVE::Storage::volume_snapshot_delete($self->{storecfg}, $volid, '__vzdump__'); };
	warn $@ if $@;
    }
}

1;
