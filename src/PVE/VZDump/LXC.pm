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

my $loop_mount_image = sub {
    my ($image_path, $mountpoint) = @_;
    
    my $loopdev;
    my $mounted;
    eval {
	my $parser = sub {
	    my $line = shift;
	    $loopdev = $line if $line =~m|^/dev/loop\d+$|;
	};
	PVE::Tools::run_command(['losetup', '--find', '--show', $image_path], outfunc => $parser);

	File::Path::mkpath($mountpoint);
	PVE::Tools::run_command(['mount', '-t', 'ext4', $loopdev, $mountpoint]);
	$mounted = 1;
    };
    if (my $err = $@) {
	if ($mounted) {
	    eval { PVE::Tools::run_command(['umount', '-d', $mountpoint]) };
	    warn $@ if $@;
	} else {
	    eval { PVE::Tools::run_command(['losetup', '-d', $loopdev]) if $loopdev; };
	    warn $@ if $@;
	}
	die $err;
    }
};

sub prepare {
    my ($self, $task, $vmid, $mode) = @_;

    my $conf = $self->{vmlist}->{$vmid} = PVE::LXC::load_config($vmid);

    my $running = PVE::LXC::check_running($vmid);

    my $diskinfo = {};
    $task->{diskinfo} = $diskinfo;

    $task->{hostname} = $conf->{'lxc.utsname'} || "CT$vmid";

    my $volid = $conf->{'pve.volid'};

    # fixme: whe do we deactivate ??
    PVE::Storage::activate_volumes($self->{storecfg}, [$volid]) if $volid;

    my $rootfs = $conf->{'lxc.rootfs'};

    if ($mode eq 'snapshot') {

	die "mode failure - storage does not support snapshots (no volid)\n" 
	    if !$volid;

	die "mode failure - storage does not support snapshots\n"
	    if !PVE::Storage::volume_has_feature($self->{storecfg}, 'snapshot', $volid);
	
	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	my $scfg = PVE::Storage::storage_config($self->{storecfg}, $sid);

	# we only handle well known types for now, because the storage
	# library dos not handle mount/unmount of snapshots

	if ($scfg->{type} ne 'zfs') {
	    $diskinfo->{mountpoint} = "/mnt/vzsnap0";
	} else {
	    die "mode failure - storage does not support snapshot mount\n"
	}
	
	PVE::Storage::volume_snapshot($self->{storecfg}, $volid, '__vzdump__');
	$task->{cleanup}->{snap_volid} = $volid;
	
	# $diskinfo->{dir} = $rootfs;
	die "implement me";
	
    } else {

	if ($rootfs =~ m!^/! && -d $rootfs) {
	    $diskinfo->{dir} = $rootfs;
	} else {
	    if ($mode eq 'stop') {
		my $mountpoint = "/mnt/vzsnap0";
		my $path = PVE::Storage::path($self->{storecfg}, $volid);
		&$loop_mount_image($path, $mountpoint);
		$task->{cleanup}->{snapshot_mount} = 1;
		$diskinfo->{dir} = $diskinfo->{mountpoint} = $mountpoint;
	    } elsif ($mode eq 'suspend') {
		my $tasks_fn = "/sys/fs/cgroup/cpu/lxc/$vmid/tasks";
		my $init_pid = PVE::Tools::file_read_firstline($tasks_fn);
		if ($init_pid =~ m/^(\d+)$/) { 
		    $diskinfo->{dir} = "/proc/$1/root";
		} else {
		    die "unable to find container init task\n";
		}
	    } else {
		die "unknown mode '$mode'\n"; # should not happen
	    }
	}

	
	if ($mode eq 'suspend') {
	    $task->{snapdir} = $task->{tmpdir};
	} else {
	    $task->{snapdir} = $diskinfo->{dir};
	}
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

    my $conffile = PVE::LXC::config_file($vmid);

    my $dir = $task->{snapdir};

    $task->{cleanup}->{etc_vzdump} = 1;

    mkpath "$dir/etc/vzdump/";
    $self->cmd ("cp '$conffile' '$dir/etc/vzdump/lxc.conf'");
}

sub archive {
    my ($self, $task, $vmid, $filename, $comp) = @_;
    
    my $findexcl = $self->{vzdump}->{findexcl};
    my $findargs = join (' ', @$findexcl) . ' -print0';
    my $opts = $self->{vzdump}->{opts};

    my $srcdir = $task->{diskinfo}->{dir};
    my $snapdir = $task->{snapdir};

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
    $cmd .= "tar cpf - $taropts etc/vzdump/lxc.conf --null -T -";
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

    if ($task->{cleanup}->{snapshot_mount}) {
	# Note: sleep to avoid 'device is busy' message.
	# Seems Kernel need some time to cleanup open file list,
	# for example when we stop the tar with kill (stop task)
	# We use -d to automatically free used loop devices
	sleep(1); 
	$self->cmd_noerr("umount -d $di->{mountpoint}");
    }

    if (my $volid = $task->{cleanup}->{snap_volid}) {
	eval { PVE::Storage::volume_snapshot_delete($self->{storecfg}, $volid, '__vzdump__'); };
	warn $@ if $@;
    }
    
    if ($task->{cleanup}->{etc_vzdump}) {
	my $dir = "$task->{snapdir}/etc/vzdump";
	eval { rmtree $dir if -d $dir; };
	$self->logerr ($@) if $@;
    }

}

1;
