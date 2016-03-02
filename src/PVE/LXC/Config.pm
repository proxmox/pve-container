package PVE::LXC::Config;

use strict;
use warnings;

use PVE::AbstractConfig;
use PVE::Cluster qw(cfs_register_file);
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools;

use base qw(PVE::AbstractConfig);

my $nodename = PVE::INotify::nodename();
my $lock_handles =  {};
my $lockdir = "/run/lock/lxc";
mkdir $lockdir;
mkdir "/etc/pve/nodes/$nodename/lxc";
my $MAX_MOUNT_POINTS = 10;
my $MAX_UNUSED_DISKS = $MAX_MOUNT_POINTS;

# BEGIN implemented abstract methods from PVE::AbstractConfig

sub guest_type {
    return "CT";
}

sub __config_max_unused_disks {
    my ($class) = @_;

    return $MAX_UNUSED_DISKS;
}

sub config_file_lock {
    my ($class, $vmid) = @_;

    return "$lockdir/pve-config-${vmid}.lock";
}

sub cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/lxc/$vmid.conf";
}

sub has_feature {
    my ($class, $feature, $conf, $storecfg, $snapname, $running, $backup_only) = @_;
    my $err;

    $class->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	return if $err; # skip further test
	return if $backup_only && $ms ne 'rootfs' && !$mountpoint->{backup};

	$err = 1
	    if !PVE::Storage::volume_has_feature($storecfg, $feature,
						 $mountpoint->{volume},
						 $snapname, $running);
    });

    return $err ? 0 : 1;
}

sub __snapshot_save_vmstate {
    my ($class, $vmid, $conf, $snapname, $storecfg) = @_;
    die "implement me - snapshot_save_vmstate\n";
}

sub __snapshot_check_running {
    my ($class, $vmid) = @_;
    return PVE::LXC::check_running($vmid);
}

sub __snapshot_check_freeze_needed {
    my ($class, $vmid, $config, $save_vmstate) = @_;

    my $ret = $class->__snapshot_check_running($vmid);
    return ($ret, $ret);
}

sub __snapshot_freeze {
    my ($class, $vmid, $unfreeze) = @_;

    if ($unfreeze) {
	eval { PVE::Tools::run_command(['/usr/bin/lxc-unfreeze', '-n', $vmid]); };
	warn $@ if $@;
    } else {
	PVE::Tools::run_command(['/usr/bin/lxc-freeze', '-n', $vmid]);
	PVE::LXC::sync_container_namespace($vmid);
    }
}

sub __snapshot_create_vol_snapshot {
    my ($class, $vmid, $ms, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();

    return if $snapname eq 'vzdump' && $ms ne 'rootfs' && !$mountpoint->{backup};
    PVE::Storage::volume_snapshot($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_delete_remove_drive {
    my ($class, $snap, $remove_drive) = @_;

    if ($remove_drive eq 'vmstate') {
	die "implement me - saving vmstate\n";
    } else {
	my $value = $snap->{$remove_drive};
	my $mountpoint = $remove_drive eq 'rootfs' ? PVE::LXC::parse_ct_rootfs($value, 1) : PVE::LXC::parse_ct_mountpoint($value, 1);
	delete $snap->{$remove_drive};
	$class->add_unused_volume($snap, $mountpoint->{volume});
    }
}

sub __snapshot_delete_vmstate_file {
    my ($class, $snap, $force) = @_;

    die "implement me - saving vmstate\n";
}

sub __snapshot_delete_vol_snapshot {
    my ($class, $vmid, $ms, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_delete($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_rollback_vol_possible {
    my ($class, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_rollback_is_possible($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_rollback_vol_rollback {
    my ($class, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_rollback($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_rollback_vm_stop {
    my ($class, $vmid) = @_;

    PVE::Tools::run_command(['/usr/bin/lxc-stop', '-n', $vmid, '--kill'])
	if $class->__snapshot_check_running($vmid);
}

sub __snapshot_rollback_vm_start {
    my ($class, $vmid, $vmstate, $forcemachine);

    die "implement me - save vmstate\n";
}

sub __snapshot_foreach_volume {
    my ($class, $conf, $func) = @_;

    $class->foreach_mountpoint($conf, $func);
}

# END implemented abstract methods from PVE::AbstractConfig

sub classify_mountpoint {
    my ($class, $vol) = @_;
    if ($vol =~ m!^/!) {
	return 'device' if $vol =~ m!^/dev/!;
	return 'bind';
    }
    return 'volume';
}

sub is_volume_in_use {
    my ($class, $config, $volid, $include_snapshots) = @_;
    my $used = 0;

    $class->foreach_mountpoint($config, sub {
	my ($ms, $mountpoint) = @_;
	return if $used;
	$used = $mountpoint->{type} eq 'volume' && $mountpoint->{volume} eq $volid;
    });

    my $snapshots = $config->{snapshots};
    if ($include_snapshots && $snapshots) {
	foreach my $snap (keys %$snapshots) {
	    $used ||= $class->is_volume_in_use($snapshots->{$snap}, $volid);
	}
    }

    return $used;
}

sub has_dev_console {
    my ($class, $conf) = @_;

    return !(defined($conf->{console}) && !$conf->{console});
}

sub mountpoint_names {
    my ($class, $reverse) = @_;

    my @names = ('rootfs');

    for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
	push @names, "mp$i";
    }

    return $reverse ? reverse @names : @names;
}

sub foreach_mountpoint_full {
    my ($class, $conf, $reverse, $func) = @_;

    foreach my $key ($class->mountpoint_names($reverse)) {
	my $value = $conf->{$key};
	next if !defined($value);
	my $mountpoint = $key eq 'rootfs' ? PVE::LXC::parse_ct_rootfs($value, 1) : PVE::LXC::parse_ct_mountpoint($value, 1);
	next if !defined($mountpoint);

	&$func($key, $mountpoint);
    }
}

sub foreach_mountpoint {
    my ($class, $conf, $func) = @_;

    $class->foreach_mountpoint_full($conf, 0, $func);
}

sub foreach_mountpoint_reverse {
    my ($class, $conf, $func) = @_;

    $class->foreach_mountpoint_full($conf, 1, $func);
}

sub get_vm_volumes {
    my ($class, $conf, $excludes) = @_;

    my $vollist = [];

    $class->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	return if $excludes && $ms eq $excludes;

	my $volid = $mountpoint->{volume};
	return if !$volid || $mountpoint->{type} ne 'volume';

	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	return if !$sid;

	push @$vollist, $volid;
    });

    return $vollist;
}

return 1;
