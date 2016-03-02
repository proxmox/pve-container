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

    PVE::LXC::foreach_mountpoint($conf, sub {
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

    PVE::LXC::foreach_mountpoint($conf, $func);
}

# END implemented abstract methods from PVE::AbstractConfig

return 1;
