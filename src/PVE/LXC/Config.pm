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

sub config_file_lock {
    my ($class, $vmid) = @_;

    return "$lockdir/pve-config-${vmid}.lock";
}

sub cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/lxc/$vmid.conf";
}

# END implemented abstract methods from PVE::AbstractConfig

return 1;
