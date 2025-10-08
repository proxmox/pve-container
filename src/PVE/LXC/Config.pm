package PVE::LXC::Config;

use strict;
use warnings;

use Fcntl qw(O_RDONLY);

use PVE::AbstractConfig;
use PVE::Cluster qw(cfs_register_file);
use PVE::DataCenterConfig;
use PVE::GuestHelpers;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools;

use PVE::LXC;
use PVE::LXC::Tools;

use base qw(PVE::AbstractConfig);

use constant {
    FIFREEZE => 0xc0045877,
    FITHAW => 0xc0045878,
};

my $have_sdn;
eval {
    require PVE::Network::SDN::Vnets;
    $have_sdn = 1;
};

my $nodename = PVE::INotify::nodename();
my $lock_handles = {};
my $lockdir = "/run/lock/lxc";
mkdir $lockdir;
mkdir "/etc/pve/nodes/$nodename/lxc";
my $MAX_MOUNT_POINTS = 256;
my $MAX_UNUSED_DISKS = $MAX_MOUNT_POINTS;
my $MAX_DEVICES = 256;

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

sub mountpoint_backup_enabled {
    my ($class, $mp_key, $mountpoint) = @_;

    my $enabled;
    my $reason;

    if ($mp_key eq 'rootfs') {
        $enabled = 1;
        $reason = 'rootfs';
    } elsif ($mountpoint->{type} ne 'volume') {
        $enabled = 0;
        $reason = 'not a volume';
    } elsif ($mountpoint->{backup}) {
        $enabled = 1;
        $reason = 'enabled';
    } else {
        $enabled = 0;
        $reason = 'disabled';
    }
    return wantarray ? ($enabled, $reason) : $enabled;
}

sub has_feature {
    my ($class, $feature, $conf, $storecfg, $snapname, $running, $backup_only) = @_;
    my $err;

    my $opts;
    if ($feature eq 'copy' || $feature eq 'clone') {
        $opts = { 'valid_target_formats' => ['raw', 'subvol'] };
    }

    $class->foreach_volume(
        $conf,
        sub {
            my ($ms, $mountpoint) = @_;

            return if $err; # skip further test
            return if $backup_only && !$class->mountpoint_backup_enabled($ms, $mountpoint);

            $err = 1
                if !PVE::Storage::volume_has_feature(
                    $storecfg, $feature, $mountpoint->{volume}, $snapname, $running, $opts,
                );
        },
    );

    return $err ? 0 : 1;
}

sub __snapshot_save_vmstate {
    my ($class, $vmid, $conf, $snapname, $storecfg) = @_;
    die "implement me - snapshot_save_vmstate\n";
}

sub __snapshot_activate_storages {
    my ($class, $conf, $include_vmstate) = @_;

    my $storecfg = PVE::Storage::config();
    my $opts = $include_vmstate ? { 'extra_keys' => ['vmstate'] } : {};
    my $storage_hash = {};

    $class->foreach_volume_full(
        $conf,
        $opts,
        sub {
            my ($vs, $mountpoint) = @_;

            return if $mountpoint->{type} ne 'volume';

            my ($storeid) = PVE::Storage::parse_volume_id($mountpoint->{volume});
            $storage_hash->{$storeid} = 1;
        },
    );

    PVE::Storage::activate_storage_list($storecfg, [sort keys $storage_hash->%*]);
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

# implements similar functionality to fsfreeze(8)
sub fsfreeze_mountpoint {
    my ($path, $thaw) = @_;

    my $op = $thaw ? 'thaw' : 'freeze';
    my $ioctl = $thaw ? FITHAW : FIFREEZE;

    sysopen my $fd, $path, O_RDONLY or die "failed to open $path: $!\n";
    my $ioctl_err;
    if (!ioctl($fd, $ioctl, 0)) {
        $ioctl_err = "$!";
    }
    close($fd);
    die "fs$op '$path' failed - $ioctl_err\n" if defined $ioctl_err;
}

sub __snapshot_freeze {
    my ($class, $vmid, $unfreeze) = @_;

    my $conf = $class->load_config($vmid);
    my $storagecfg = PVE::Storage::config();

    my $freeze_mps = [];
    $class->foreach_volume(
        $conf,
        sub {
            my ($ms, $mountpoint) = @_;

            return if $mountpoint->{type} ne 'volume';

            if (PVE::Storage::volume_snapshot_needs_fsfreeze(
                $storagecfg, $mountpoint->{volume},
            )) {
                push @$freeze_mps, $mountpoint->{mp};
            }
        },
    );

    my $freeze_mountpoints = sub {
        my ($thaw) = @_;

        return if scalar(@$freeze_mps) == 0;

        my $pid = PVE::LXC::find_lxc_pid($vmid);

        for my $mp (@$freeze_mps) {
            eval { fsfreeze_mountpoint("/proc/${pid}/root/${mp}", $thaw); };
            warn $@ if $@;
        }
    };

    if ($unfreeze) {
        eval { PVE::LXC::thaw($vmid); };
        warn $@ if $@;
        $freeze_mountpoints->(1);
    } else {
        PVE::LXC::freeze($vmid);
        PVE::LXC::sync_container_namespace($vmid);
        $freeze_mountpoints->(0);
    }
}

sub __snapshot_create_vol_snapshot {
    my ($class, $vmid, $ms, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();

    return
        if $snapname eq 'vzdump'
        && !$class->mountpoint_backup_enabled($ms, $mountpoint);

    PVE::Storage::volume_snapshot($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_delete_remove_drive {
    my ($class, $snap, $remove_drive) = @_;

    if ($remove_drive eq 'vmstate') {
        die "implement me - saving vmstate\n";
    } else {
        my $value = $snap->{$remove_drive};
        my $mountpoint = $class->parse_volume($remove_drive, $value, 1);
        delete $snap->{$remove_drive};

        $class->add_unused_volume($snap, $mountpoint->{volume})
            if $mountpoint && ($mountpoint->{type} eq 'volume');
    }
}

sub __snapshot_delete_vmstate_file {
    my ($class, $snap, $force) = @_;

    die "implement me - saving vmstate\n";
}

sub __snapshot_delete_vol_snapshot {
    my ($class, $vmid, $ms, $mountpoint, $snapname, $unused) = @_;

    return
        if $snapname eq 'vzdump'
        && !$class->mountpoint_backup_enabled($ms, $mountpoint);

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_delete($storecfg, $mountpoint->{volume}, $snapname);
    push @$unused, $mountpoint->{volume};
}

sub __snapshot_rollback_vol_possible {
    my ($class, $mountpoint, $snapname, $blockers) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_rollback_is_possible(
        $storecfg, $mountpoint->{volume}, $snapname, $blockers,
    );
}

sub __snapshot_rollback_vol_rollback {
    my ($class, $mountpoint, $snapname) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_rollback($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_rollback_vm_stop {
    my ($class, $vmid) = @_;

    PVE::LXC::vm_stop($vmid, 1)
        if $class->__snapshot_check_running($vmid);
}

sub __snapshot_rollback_vm_start {
    my ($class, $vmid, $vmstate, $data);

    die "implement me - save vmstate\n";
}

sub __snapshot_rollback_get_unused {
    my ($class, $conf, $snap) = @_;

    my $unused = [];

    $class->foreach_volume(
        $conf,
        sub {
            my ($vs, $volume) = @_;

            return if $volume->{type} ne 'volume';

            my $found = 0;
            my $volid = $volume->{volume};

            $class->foreach_volume(
                $snap,
                sub {
                    my ($ms, $mountpoint) = @_;

                    return if $found;
                    return if ($mountpoint->{type} ne 'volume');

                    $found = 1
                        if ($mountpoint->{volume} && $mountpoint->{volume} eq $volid);
                },
            );

            push @$unused, $volid if !$found;
        },
    );

    return $unused;
}

# END implemented abstract methods from PVE::AbstractConfig

# BEGIN JSON config code

cfs_register_file('/lxc/', \&parse_pct_config, \&write_pct_config);

my $valid_mount_option_re = qr/(discard|lazytime|noatime|nodev|noexec|nosuid)/;
my $valid_ro_mount_option_re = qr/(nodev|noexec|nosuid)/;

sub is_valid_mount_option {
    my ($option) = @_;
    return $option =~ $valid_mount_option_re;
}

sub is_valid_ro_mount_option {
    my ($option) = @_;
    return $option =~ $valid_ro_mount_option_re;
}

my $rootfs_desc = {
    volume => {
        type => 'string',
        default_key => 1,
        format => 'pve-lxc-mp-string',
        format_description => 'volume',
        description => 'Volume, device or directory to mount into the container.',
    },
    size => {
        type => 'string',
        format => 'disk-size',
        format_description => 'DiskSize',
        description => 'Volume size (read only value).',
        optional => 1,
    },
    acl => {
        type => 'boolean',
        description => 'Explicitly enable or disable ACL support.',
        optional => 1,
    },
    mountoptions => {
        optional => 1,
        type => 'string',
        description => 'Extra mount options for rootfs/mps.',
        format_description => 'opt[;opt...]',
        pattern => qr/$valid_mount_option_re(;$valid_mount_option_re)*/,
    },
    ro => {
        type => 'boolean',
        description => 'Read-only mount point',
        optional => 1,
    },
    quota => {
        type => 'boolean',
        description =>
            'Enable user quotas inside the container (not supported with zfs subvolumes)',
        optional => 1,
    },
    replicate => {
        type => 'boolean',
        description => 'Will include this volume to a storage replica job.',
        optional => 1,
        default => 1,
    },
    shared => {
        type => 'boolean',
        description =>
            'Mark this non-volume mount point as available on multiple nodes (see \'nodes\')',
        verbose_description =>
            "Mark this non-volume mount point as available on all nodes.\n\nWARNING: This option does not share the mount point automatically, it assumes it is shared already!",
        optional => 1,
        default => 0,
    },
};

PVE::JSONSchema::register_standard_option(
    'pve-ct-rootfs',
    {
        type => 'string',
        format => $rootfs_desc,
        description => "Use volume as container root.",
        optional => 1,
    },
);

# IP address with optional interface suffix for link local ipv6 addresses
PVE::JSONSchema::register_format('lxc-ip-with-ll-iface', \&verify_ip_with_ll_iface);

sub verify_ip_with_ll_iface {
    my ($addr, $noerr) = @_;

    if (my ($addr, $iface) = ($addr =~ /^(fe80:[^%]+)%(.*)$/)) {
        if (
            PVE::JSONSchema::pve_verify_ip($addr, 1)
            && PVE::JSONSchema::pve_verify_iface($iface, 1)
        ) {
            return $addr;
        }
    }

    return PVE::JSONSchema::pve_verify_ip($addr, $noerr);
}

my $features_desc = {
    mount => {
        optional => 1,
        type => 'string',
        description => "Allow mounting file systems of specific types."
            . " This should be a list of file system types as used with the mount command."
            . " Note that this can have negative effects on the container's security."
            . " With access to a loop device, mounting a file can circumvent the mknod"
            . " permission of the devices cgroup, mounting an NFS file system can"
            . " block the host's I/O completely and prevent it from rebooting, etc.",
        format_description => 'fstype;fstype;...',
        pattern => qr/[a-zA-Z0-9_; ]+/,
    },
    nesting => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description => "Allow nesting."
            . " Best used with unprivileged containers with additional id mapping."
            . " Note that this will expose procfs and sysfs contents of the host"
            . " to the guest. This is also required by systemd to isolate services.",
    },
    keyctl => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description =>
            "For unprivileged containers only: Allow the use of the keyctl() system call."
            . " This is required to use docker inside a container."
            . " By default unprivileged containers will see this system call as non-existent."
            . " This is mostly a workaround for systemd-networkd, as it will treat it as a fatal"
            . " error when some keyctl() operations are denied by the kernel due to lacking permissions."
            . " Essentially, you can choose between running systemd-networkd or docker.",
    },
    fuse => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description => "Allow using 'fuse' file systems in a container."
            . " Note that interactions between fuse and the freezer cgroup can potentially cause I/O deadlocks.",
    },
    mknod => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description =>
            "Allow unprivileged containers to use mknod() to add certain device nodes."
            . " This requires a kernel with seccomp trap to user space support (5.3 or newer)."
            . " This is experimental.",
    },
    force_rw_sys => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description => "Mount /sys in unprivileged containers as `rw` instead of `mixed`."
            . " This can break networking under newer (>= v245) systemd-network use.",
    },
};

my $confdesc = {
    lock => {
        optional => 1,
        type => 'string',
        description => "Lock/unlock the container.",
        enum => [
            qw(backup create destroyed disk fstrim migrate mounted rollback snapshot snapshot-delete)
        ],
    },
    onboot => {
        optional => 1,
        type => 'boolean',
        description => "Specifies whether a container will be started during system bootup.",
        default => 0,
    },
    startup => get_standard_option('pve-startup-order'),
    template => {
        optional => 1,
        type => 'boolean',
        description => "Enable/disable Template.",
        default => 0,
    },
    arch => {
        optional => 1,
        type => 'string',
        enum => ['amd64', 'i386', 'arm64', 'armhf', 'riscv32', 'riscv64'],
        description => "OS architecture type.",
        default => 'amd64',
    },
    ostype => {
        optional => 1,
        type => 'string',
        enum => [
            qw(debian devuan ubuntu centos fedora opensuse archlinux alpine gentoo nixos unmanaged)
        ],
        description =>
            "OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/<ostype>.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.",
    },
    console => {
        optional => 1,
        type => 'boolean',
        description => "Attach a console device (/dev/console) to the container.",
        default => 1,
    },
    tty => {
        optional => 1,
        type => 'integer',
        description => "Specify the number of tty available to the container",
        minimum => 0,
        maximum => 6,
        default => 2,
    },
    cores => {
        optional => 1,
        type => 'integer',
        description =>
            "The number of cores assigned to the container. A container can use all available cores by default.",
        minimum => 1,
        maximum => 8192,
    },
    cpulimit => {
        optional => 1,
        type => 'number',
        description =>
            "Limit of CPU usage.\n\nNOTE: If the computer has 2 CPUs, it has a total of '2' CPU time. Value '0' indicates no CPU limit.",
        minimum => 0,
        maximum => 8192,
        default => 0,
    },
    cpuunits => {
        optional => 1,
        type => 'integer',
        description =>
            "CPU weight for a container, will be clamped to [1, 10000] in cgroup v2.",
        verbose_description =>
            "CPU weight for a container. Argument is used in the kernel fair "
            . "scheduler. The larger the number is, the more CPU time this container gets. Number "
            . "is relative to the weights of all the other running guests.",
        minimum => 0,
        maximum => 500000,
        default => 'cgroup v1: 1024, cgroup v2: 100',
    },
    memory => {
        optional => 1,
        type => 'integer',
        description => "Amount of RAM for the container in MB.",
        minimum => 16,
        default => 512,
    },
    swap => {
        optional => 1,
        type => 'integer',
        description => "Amount of SWAP for the container in MB.",
        minimum => 0,
        default => 512,
    },
    hostname => {
        optional => 1,
        description => "Set a host name for the container.",
        type => 'string',
        format => 'dns-name',
        maxLength => 255,
    },
    description => {
        optional => 1,
        type => 'string',
        description => "Description for the Container. Shown in the web-interface CT's summary."
            . " This is saved as comment inside the configuration file.",
        maxLength => 1024 * 8,
    },
    ipmanagehost => {
        type => 'boolean',
        description =>
            "Whether this interface's IP configuration should be managed by the host.",
        optional => 1,
    },
    searchdomain => {
        optional => 1,
        type => 'string',
        format => 'dns-name-list',
        description =>
            "Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.",
    },
    nameserver => {
        optional => 1,
        type => 'string',
        format => 'lxc-ip-with-ll-iface-list',
        description =>
            "Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.",
    },
    timezone => {
        optional => 1,
        type => 'string',
        format => 'pve-ct-timezone',
        description =>
            "Time zone to use in the container. If option isn't set, then nothing will be done. Can be set to 'host' to match the host time zone, or an arbitrary time zone option from /usr/share/zoneinfo/zone.tab",
    },
    rootfs => get_standard_option('pve-ct-rootfs'),
    parent => {
        optional => 1,
        type => 'string',
        format => 'pve-configid',
        maxLength => 40,
        description =>
            "Parent snapshot name. This is used internally, and should not be modified.",
    },
    snaptime => {
        optional => 1,
        description => "Timestamp for snapshots.",
        type => 'integer',
        minimum => 0,
    },
    cmode => {
        optional => 1,
        description =>
            "Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).",
        type => 'string',
        enum => ['shell', 'console', 'tty'],
        default => 'tty',
    },
    entrypoint => {
        optional => 1,
        type => 'string',
        description => "Absolute path from container rootfs to the binary to use as init.",
        default => '/sbin/init',
    },
    protection => {
        optional => 1,
        type => 'boolean',
        description =>
            "Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.",
        default => 0,
    },
    unprivileged => {
        optional => 1,
        type => 'boolean',
        description =>
            "Makes the container run as unprivileged user. For creation, the default is"
            . " 1. For restore, the default is the value from the backup. (Should not be modified"
            . " manually.)",
        default => 0,
    },
    features => {
        optional => 1,
        type => 'string',
        format => $features_desc,
        description => "Allow containers access to advanced features.",
    },
    hookscript => {
        optional => 1,
        type => 'string',
        format => 'pve-volume-id',
        description =>
            'Script that will be executed during various steps in the containers lifetime.',
    },
    tags => {
        type => 'string',
        format => 'pve-tag-list',
        description => 'Tags of the Container. This is only meta information.',
        optional => 1,
    },
    debug => {
        optional => 1,
        type => 'boolean',
        description =>
            "Try to be more verbose. For now this only enables debug log-level on start.",
        default => 0,
    },
};

my $valid_lxc_conf_keys = {
    'lxc.apparmor.profile' => 1,
    'lxc.apparmor.allow_incomplete' => 1,
    'lxc.apparmor.allow_nesting' => 1,
    'lxc.apparmor.raw' => 1,
    'lxc.selinux.context' => 1,
    'lxc.include' => 1,
    'lxc.arch' => 1,
    'lxc.uts.name' => 1,
    'lxc.signal.halt' => 1,
    'lxc.signal.reboot' => 1,
    'lxc.signal.stop' => 1,
    'lxc.init.cmd' => 1,
    'lxc.init.cwd' => 1,
    'lxc.pty.max' => 1,
    'lxc.console.logfile' => 1,
    'lxc.console.path' => 1,
    'lxc.tty.max' => 1,
    'lxc.devtty.dir' => 1,
    'lxc.hook.autodev' => 1,
    'lxc.autodev' => 1,
    'lxc.kmsg' => 1,
    'lxc.mount.fstab' => 1,
    'lxc.mount.entry' => 1,
    'lxc.mount.auto' => 1,
    'lxc.rootfs.path' => 'lxc.rootfs.path is auto generated from rootfs',
    'lxc.rootfs.mount' => 1,
    'lxc.rootfs.options' => 'lxc.rootfs.options is not supported'
        . ', please use mount point options in the "rootfs" key',
    # lxc.cgroup.*
    # lxc.prlimit.*
    # lxc.net.*
    'lxc.cap.drop' => 1,
    'lxc.cap.keep' => 1,
    'lxc.seccomp.profile' => 1,
    'lxc.seccomp.notify.proxy' => 1,
    'lxc.seccomp.notify.cookie' => 1,
    'lxc.idmap' => 1,
    'lxc.hook.pre-start' => 1,
    'lxc.hook.pre-mount' => 1,
    'lxc.hook.mount' => 1,
    'lxc.hook.start' => 1,
    'lxc.hook.stop' => 1,
    'lxc.hook.post-stop' => 1,
    'lxc.hook.clone' => 1,
    'lxc.hook.destroy' => 1,
    'lxc.hook.version' => 1,
    'lxc.log.level' => 1,
    'lxc.log.file' => 1,
    'lxc.start.auto' => 1,
    'lxc.start.delay' => 1,
    'lxc.start.order' => 1,
    'lxc.group' => 1,
    'lxc.environment' => 1,
    'lxc.environment.runtime' => 1,
    'lxc.environment.hooks' => 1,

    # All these are namespaced via CLONE_NEWIPC (see namespaces(7)).
    'lxc.sysctl.fs.mqueue' => 1,
    'lxc.sysctl.kernel.msgmax' => 1,
    'lxc.sysctl.kernel.msgmnb' => 1,
    'lxc.sysctl.kernel.msgmni' => 1,
    'lxc.sysctl.kernel.sem' => 1,
    'lxc.sysctl.kernel.shmall' => 1,
    'lxc.sysctl.kernel.shmmax' => 1,
    'lxc.sysctl.kernel.shmmni' => 1,
    'lxc.sysctl.kernel.shm_rmid_forced' => 1,
};

my $deprecated_lxc_conf_keys = {
    # Deprecated (removed with lxc 3.0):
    'lxc.aa_profile' => 'lxc.apparmor.profile',
    'lxc.aa_allow_incomplete' => 'lxc.apparmor.allow_incomplete',
    'lxc.console' => 'lxc.console.path',
    'lxc.devttydir' => 'lxc.tty.dir',
    'lxc.haltsignal' => 'lxc.signal.halt',
    'lxc.rebootsignal' => 'lxc.signal.reboot',
    'lxc.stopsignal' => 'lxc.signal.stop',
    'lxc.id_map' => 'lxc.idmap',
    'lxc.init_cmd' => 'lxc.init.cmd',
    'lxc.loglevel' => 'lxc.log.level',
    'lxc.logfile' => 'lxc.log.file',
    'lxc.mount' => 'lxc.mount.fstab',
    'lxc.network.type' => 'lxc.net.INDEX.type',
    'lxc.network.flags' => 'lxc.net.INDEX.flags',
    'lxc.network.link' => 'lxc.net.INDEX.link',
    'lxc.network.mtu' => 'lxc.net.INDEX.mtu',
    'lxc.network.name' => 'lxc.net.INDEX.name',
    'lxc.network.hwaddr' => 'lxc.net.INDEX.hwaddr',
    'lxc.network.ipv4' => 'lxc.net.INDEX.ipv4.address',
    'lxc.network.ipv4.gateway' => 'lxc.net.INDEX.ipv4.gateway',
    'lxc.network.ipv6' => 'lxc.net.INDEX.ipv6.address',
    'lxc.network.ipv6.gateway' => 'lxc.net.INDEX.ipv6.gateway',
    'lxc.network.script.up' => 'lxc.net.INDEX.script.up',
    'lxc.network.script.down' => 'lxc.net.INDEX.script.down',
    'lxc.pts' => 'lxc.pty.max',
    'lxc.se_context' => 'lxc.selinux.context',
    'lxc.seccomp' => 'lxc.seccomp.profile',
    'lxc.tty' => 'lxc.tty.max',
    'lxc.utsname' => 'lxc.uts.name',
};

sub is_valid_lxc_conf_key {
    my ($vmid, $key) = @_;
    if ($key =~ /^lxc\.limit\./) {
        warn "vm $vmid - $key: lxc.limit.* was renamed to lxc.prlimit.*\n";
        return 1;
    }
    if (defined(my $new_name = $deprecated_lxc_conf_keys->{$key})) {
        warn "vm $vmid - $key is deprecated and was renamed to $new_name\n";
        return 1;
    }
    my $validity = $valid_lxc_conf_keys->{$key};
    return $validity if defined($validity);
    return 1 if $key =~ /^lxc\.cgroup2?\./ # allow all cgroup values
        || $key =~ /^lxc\.prlimit\./ # allow all prlimits
        || $key =~ /^lxc\.net\./; # allow custom network definitions
    return 0;
}

our $netconf_desc = {
    type => {
        type => 'string',
        optional => 1,
        description => "Network interface type.",
        enum => [qw(veth)],
    },
    name => {
        type => 'string',
        format_description => 'string',
        description =>
            'Name of the network device as seen from inside the container. (lxc.network.name)',
        pattern => '[-_.\w\d]+',
    },
    bridge => {
        type => 'string',
        format_description => 'bridge',
        description => 'Bridge to attach the network device to.',
        pattern => '[-_.\w\d]+',
        optional => 1,
    },
    hwaddr => get_standard_option(
        'mac-addr',
        {
            description => 'The interface MAC address. This is dynamically allocated by'
                . ' default, but you can set that statically if needed, for example to always'
                . ' have the same link-local IPv6 address. (lxc.network.hwaddr)',
        },
    ),
    mtu => {
        type => 'integer',
        description => 'Maximum transfer unit of the interface. (lxc.network.mtu)',
        minimum => 64, # minimum ethernet frame is 64 bytes
        maximum => 65535,
        optional => 1,
    },
    ip => {
        type => 'string',
        format => 'pve-ipv4-config',
        format_description => '(IPv4/CIDR|dhcp|manual)',
        description => 'IPv4 address in CIDR format.',
        optional => 1,
    },
    gw => {
        type => 'string',
        format => 'ipv4',
        format_description => 'GatewayIPv4',
        description => 'Default gateway for IPv4 traffic.',
        optional => 1,
    },
    ip6 => {
        type => 'string',
        format => 'pve-ipv6-config',
        format_description => '(IPv6/CIDR|auto|dhcp|manual)',
        description => 'IPv6 address in CIDR format.',
        optional => 1,
    },
    gw6 => {
        type => 'string',
        format => 'ipv6',
        format_description => 'GatewayIPv6',
        description => 'Default gateway for IPv6 traffic.',
        optional => 1,
    },
    firewall => {
        type => 'boolean',
        description => "Controls whether this interface's firewall rules should be used.",
        optional => 1,
    },
    tag => {
        type => 'integer',
        minimum => 1,
        maximum => 4094,
        description => "VLAN tag for this interface.",
        optional => 1,
    },
    trunks => {
        type => 'string',
        pattern => qr/\d+(?:;\d+)*/,
        format_description => 'vlanid[;vlanid...]',
        description => "VLAN ids to pass through the interface",
        optional => 1,
    },
    rate => {
        type => 'number',
        format_description => 'mbps',
        description => "Apply rate limiting to the interface",
        optional => 1,
    },
    # TODO: Rename this option and the qemu-server one to `link-down` for PVE 8.0
    link_down => {
        type => 'boolean',
        description => 'Whether this interface should be disconnected (like pulling the plug).',
        optional => 1,
    },
};
PVE::JSONSchema::register_format('pve-lxc-network', $netconf_desc);

my $MAX_LXC_NETWORKS = 32;
for (my $i = 0; $i < $MAX_LXC_NETWORKS; $i++) {
    $confdesc->{"net$i"} = {
        optional => 1,
        type => 'string',
        format => $netconf_desc,
        description => "Specifies network interfaces for the container.",
    };
}

PVE::JSONSchema::register_format('pve-ct-timezone', \&verify_ct_timezone);

sub verify_ct_timezone {
    my ($timezone, $noerr) = @_;

    return if $timezone eq 'host'; # using host settings

    PVE::JSONSchema::pve_verify_timezone($timezone);
}

PVE::JSONSchema::register_format('pve-lxc-mp-string', \&verify_lxc_mp_string);

sub verify_lxc_mp_string {
    my ($mp, $noerr) = @_;

    # do not allow:
    # /./ or /../
    # /. or /.. at the end
    # ../ at the beginning

    if (
        $mp =~ m@/\.\.?/@
        || $mp =~ m@/\.\.?$@
        || $mp =~ m@^\.\./@
    ) {
        return undef if $noerr;
        die "$mp contains illegal character sequences\n";
    }
    return $mp;
}

my $mp_desc = {
    %$rootfs_desc,
    backup => {
        type => 'boolean',
        description => 'Whether to include the mount point in backups.',
        verbose_description => 'Whether to include the mount point in backups '
            . '(only used for volume mount points).',
        optional => 1,
    },
    mp => {
        type => 'string',
        format => 'pve-lxc-mp-string',
        format_description => 'Path',
        description => 'Path to the mount point as seen from inside the container '
            . '(must not contain symlinks).',
        verbose_description => "Path to the mount point as seen from inside the container.\n\n"
            . "NOTE: Must not contain any symlinks for security reasons.",
    },
};
PVE::JSONSchema::register_format('pve-ct-mountpoint', $mp_desc);

my $unused_desc = {
    volume => {
        type => 'string',
        default_key => 1,
        format => 'pve-volume-id',
        format_description => 'volume',
        description => 'The volume that is not used currently.',
    },
};

for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"mp$i"} = {
        optional => 1,
        type => 'string',
        format => $mp_desc,
        description => "Use volume as container mount point. Use the special "
            . "syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.",
    };
}

for (my $i = 0; $i < $MAX_UNUSED_DISKS; $i++) {
    $confdesc->{"unused$i"} = {
        optional => 1,
        type => 'string',
        format => $unused_desc,
        description =>
            "Reference to unused volumes. This is used internally, and should not be modified manually.",
    };
}

PVE::JSONSchema::register_format('pve-lxc-dev-string', \&verify_lxc_dev_string);

sub verify_lxc_dev_string {
    my ($dev, $noerr) = @_;

    # do not allow /./ or /../ or /.$ or /..$
    # enforce /dev/ at the beginning

    if (
        $dev =~ m@/\.\.?(?:/|$)@
        || $dev !~ m!^/dev/!
    ) {
        return undef if $noerr;
        die "$dev is not a valid device path\n";
    }

    return $dev;
}

my $dev_desc = {
    path => {
        optional => 1,
        type => 'string',
        default_key => 1,
        format => 'pve-lxc-dev-string',
        format_description => 'Path',
        description => 'Device to pass through to the container',
        verbose_description => 'Path to the device to pass through to the container',
    },
    mode => {
        optional => 1,
        type => 'string',
        pattern => '0[0-7]{3}',
        format_description => 'Octal access mode',
        description => 'Access mode to be set on the device node',
    },
    uid => {
        optional => 1,
        type => 'integer',
        minimum => 0,
        description => 'User ID to be assigned to the device node',
    },
    gid => {
        optional => 1,
        type => 'integer',
        minimum => 0,
        description => 'Group ID to be assigned to the device node',
    },
    'deny-write' => {
        optional => 1,
        type => 'boolean',
        description => 'Deny the container to write to the device',
        default => 0,
    },
};

for (my $i = 0; $i < $MAX_DEVICES; $i++) {
    $confdesc->{"dev$i"} = {
        optional => 1,
        type => 'string',
        format => $dev_desc,
        description => "Device to pass through to the container",
    };
}

sub parse_pct_config {
    my ($filename, $raw, $strict) = @_;

    return undef if !defined($raw);

    my $res = {
        digest => Digest::SHA::sha1_hex($raw),
        snapshots => {},
        pending => {},
    };

    my $handle_error = sub {
        my ($msg) = @_;

        if ($strict) {
            die $msg;
        } else {
            warn $msg;
        }
    };

    $filename =~ m|/lxc/(\d+).conf$|
        || die "got strange filename '$filename'";

    my $vmid = $1;

    my $conf = $res;
    my $descr = '';
    my $section = '';

    my @lines = split(/\n/, $raw);
    foreach my $line (@lines) {
        next if $line =~ m/^\s*$/;

        if ($line =~ m/^\[pve:pending\]\s*$/i) {
            $section = 'pending';
            $conf->{description} = $descr if $descr;
            $descr = '';
            $conf = $res->{$section} = {};
            next;
        } elsif ($line =~ m/^\[([a-z][a-z0-9_\-]+)\]\s*$/i) {
            $section = $1;
            $conf->{description} = $descr if $descr;
            $descr = '';
            $conf = $res->{snapshots}->{$section} = {};
            next;
        }

        if ($line =~ m/^\#(.*)$/) {
            $descr .= PVE::Tools::decode_text($1) . "\n";
            next;
        }

        if ($line =~ m/^(lxc\.[a-z0-9_\-\.]+)(:|\s*=)\s*(.*?)\s*$/) {
            my $key = $1;
            my $value = $3;
            my $validity = is_valid_lxc_conf_key($vmid, $key);
            if ($validity eq 1) {
                push @{ $conf->{lxc} }, [$key, $value];
            } elsif (my $errmsg = $validity) {
                $handle_error->("vm $vmid - $key: $errmsg\n");
            } else {
                $handle_error->("vm $vmid - unable to parse config: $line\n");
            }
        } elsif ($line =~ m/^(description):\s*(.*\S)\s*$/) {
            $descr .= PVE::Tools::decode_text($2);
        } elsif ($line =~ m/snapstate:\s*(prepare|delete)\s*$/) {
            $conf->{snapstate} = $1;
        } elsif ($line =~ m/^delete:\s*(.*\S)\s*$/) {
            my $value = $1;
            if ($section eq 'pending') {
                $conf->{delete} = $value;
            } else {
                $handle_error->("vm $vmid - property 'delete' is only allowed in [pve:pending]\n");
            }
        } elsif ($line =~ m/^([a-z][a-z_]*\d*):\s*(.+?)\s*$/) {
            my $key = $1;
            my $value = $2;
            eval { $value = PVE::LXC::Config->check_type($key, $value); };
            $handle_error->("vm $vmid - unable to parse value of '$key' - $@") if $@;
            $conf->{$key} = $value;
        } else {
            $handle_error->("vm $vmid - unable to parse config: $line\n");
        }
    }

    $conf->{description} = $descr if $descr;

    delete $res->{snapstate}; # just to be sure

    return $res;
}

sub write_pct_config {
    my ($filename, $conf) = @_;

    delete $conf->{snapstate}; # just to be sure

    my $volidlist = PVE::LXC::Config->get_vm_volumes($conf);
    my $used_volids = {};
    foreach my $vid (@$volidlist) {
        $used_volids->{$vid} = 1;
    }

    # remove 'unusedX' settings if the volume is still used
    foreach my $key (keys %$conf) {
        my $value = $conf->{$key};
        if ($key =~ m/^unused/ && $used_volids->{$value}) {
            delete $conf->{$key};
        }
    }

    my $generate_raw_config = sub {
        my ($conf) = @_;

        my $raw = '';

        # add description as comment to top of file
        my $descr = $conf->{description} || '';
        foreach my $cl (split(/\n/, $descr)) {
            $raw .= '#' . PVE::Tools::encode_text($cl) . "\n";
        }

        foreach my $key (sort keys %$conf) {
            next
                if $key eq 'digest'
                || $key eq 'description'
                || $key eq 'pending'
                || $key eq 'snapshots'
                || $key eq 'snapname'
                || $key eq 'lxc';
            my $value = $conf->{$key};
            die "detected invalid newline inside property '$key'\n"
                if $value =~ m/\n/;
            $raw .= "$key: $value\n";
        }

        if (my $lxcconf = $conf->{lxc}) {
            foreach my $entry (@$lxcconf) {
                my ($k, $v) = @$entry;
                $raw .= "$k: $v\n";
            }
        }

        return $raw;
    };

    my $raw = &$generate_raw_config($conf);

    if (scalar(keys %{ $conf->{pending} })) {
        $raw .= "\n[pve:pending]\n";
        $raw .= &$generate_raw_config($conf->{pending});
    }

    foreach my $snapname (sort keys %{ $conf->{snapshots} }) {
        $raw .= "\n[$snapname]\n";
        $raw .= &$generate_raw_config($conf->{snapshots}->{$snapname});
    }

    return $raw;
}

sub update_pct_config {
    my ($class, $vmid, $conf, $running, $param, $delete, $revert) = @_;

    my $storage_cfg = PVE::Storage::config();

    foreach my $opt (@$revert) {
        delete $conf->{pending}->{$opt};
        $class->remove_from_pending_delete($conf, $opt); # also remove from deletion queue
    }

    # write updates to pending section
    my $modified = {}; # record modified options

    foreach my $opt (@$delete) {
        if (!defined($conf->{$opt}) && !defined($conf->{pending}->{$opt})) {
            warn "cannot delete '$opt' - not set in current configuration!\n";
            next;
        }
        $modified->{$opt} = 1;
        if ($opt eq 'memory' || $opt eq 'rootfs' || $opt eq 'ostype') {
            die "unable to delete required option '$opt'\n";
        } elsif ($opt =~ m/^unused(\d+)$/) {
            $class->check_protection($conf, "can't remove CT $vmid drive '$opt'");
        } elsif ($opt =~ m/^mp(\d+)$/) {
            $class->check_protection($conf, "can't remove CT $vmid drive '$opt'");
        } elsif ($opt eq 'unprivileged') {
            die "unable to delete read-only option: '$opt'\n";
        }
        $class->add_to_pending_delete($conf, $opt);
    }

    my $check_content_type = sub {
        my ($mp) = @_;
        my $sid = PVE::Storage::parse_volume_id($mp->{volume});
        my $storage_config = PVE::Storage::storage_config($storage_cfg, $sid);
        die "storage '$sid' does not allow content type 'rootdir' (Container)\n"
            if !$storage_config->{content}->{rootdir};
    };

    foreach my $opt (sort keys %$param) { # add/change
        $modified->{$opt} = 1;
        my $value = $param->{$opt};
        if ($opt =~ m/^mp(\d+)$/ || $opt eq 'rootfs') {
            $class->check_protection($conf, "can't update CT $vmid drive '$opt'");
            my $mp = $class->parse_volume($opt, $value);
            $check_content_type->($mp) if ($mp->{type} eq 'volume');
        } elsif ($opt eq 'hookscript') {
            PVE::GuestHelpers::check_hookscript($value);
        } elsif ($opt eq 'nameserver') {
            $value = PVE::LXC::verify_nameserver_list($value);
        } elsif ($opt eq 'searchdomain') {
            $value = PVE::LXC::verify_searchdomain_list($value);
        } elsif ($opt eq 'unprivileged') {
            die "unable to modify read-only option: '$opt'\n";
        } elsif ($opt eq 'tags') {
            $value = PVE::GuestHelpers::get_unique_tags($value);
        } elsif ($opt =~ m/^net(\d+)$/) {
            my $res = PVE::JSONSchema::parse_property_string($netconf_desc, $value);

            if (my $mtu = $res->{mtu}) {
                my $bridge_mtu = PVE::Network::read_bridge_mtu($res->{bridge});
                die "$opt: MTU size '$mtu' is bigger than bridge MTU '$bridge_mtu'\n"
                    if ($mtu > $bridge_mtu);
            }

            if (
                (!defined($res->{link_down}) || $res->{link_down} != 1)
                && $conf->{ipmanagehost}
                && defined($res->{ip6})
                && $res->{ip6} eq 'auto'
            ) {
                die "$opt: SLAAC is not supported with ipmanagehost\n";
            }
        } elsif ($opt =~ m/^dev(\d+)$/) {
            my $device = $class->parse_device($value);

            die "Path is not defined for passthrough device $opt"
                if !defined($device->{path});

            # Validate device
            PVE::LXC::Tools::get_device_mode_and_rdev($device->{path});
        }
        $conf->{pending}->{$opt} = $value;
        $class->remove_from_pending_delete($conf, $opt);
    }

    my $changes = $class->cleanup_pending($conf);

    my $errors = {};
    if ($running) {
        $class->vmconfig_hotplug_pending($vmid, $conf, $storage_cfg, $modified, $errors);
    } else {
        $class->vmconfig_apply_pending($vmid, $conf, $storage_cfg, $modified, $errors);
    }

    return $errors;
}

sub check_type {
    my ($class, $key, $value) = @_;

    die "unknown setting '$key'\n" if !$confdesc->{$key};

    my $type = $confdesc->{$key}->{type};

    if (!defined($value)) {
        die "got undefined value\n";
    }

    if ($value =~ m/[\n\r]/) {
        die "property contains a line feed\n";
    }

    if ($type eq 'boolean') {
        return 1 if ($value eq '1') || ($value =~ m/^(on|yes|true)$/i);
        return 0 if ($value eq '0') || ($value =~ m/^(off|no|false)$/i);
        die "type check ('boolean') failed - got '$value'\n";
    } elsif ($type eq 'integer') {
        return int($1) if $value =~ m/^(\d+)$/;
        die "type check ('integer') failed - got '$value'\n";
    } elsif ($type eq 'number') {
        return $value if $value =~ m/^(\d+)(\.\d+)?$/;
        die "type check ('number') failed - got '$value'\n";
    } elsif ($type eq 'string') {
        if (my $fmt = $confdesc->{$key}->{format}) {
            PVE::JSONSchema::check_format($fmt, $value);
            return $value;
        }
        return $value;
    } else {
        die "internal error";
    }
}

# add JSON properties for create and set function
sub json_config_properties {
    my ($class, $prop) = @_;

    foreach my $opt (keys %$confdesc) {
        next if $opt eq 'parent' || $opt eq 'snaptime';
        next if $prop->{$opt};
        $prop->{$opt} = $confdesc->{$opt};
    }

    return $prop;
}

my $parse_ct_mountpoint_full = sub {
    my ($class, $desc, $data, $noerr) = @_;

    $data //= '';

    my $res;
    eval { $res = PVE::JSONSchema::parse_property_string($desc, $data) };
    if ($@) {
        return undef if $noerr;
        die $@;
    }

    if (defined(my $size = $res->{size})) {
        $size = PVE::JSONSchema::parse_size($size);
        if (!defined($size)) {
            return undef if $noerr;
            die "invalid size: $size\n";
        }
        $res->{size} = $size;
    }

    $res->{type} = $class->classify_mountpoint($res->{volume});

    return $res;
};

sub print_ct_mountpoint {
    my ($class, $info, $nomp) = @_;
    my $skip = ['type'];
    push @$skip, 'mp' if $nomp;
    return PVE::JSONSchema::print_property_string($info, $mp_desc, $skip);
}

sub print_ct_unused {
    my ($class, $info) = @_;

    my $skip = ['type'];
    return PVE::JSONSchema::print_property_string($info, $unused_desc, $skip);
}

sub parse_volume {
    my ($class, $key, $volume_string, $noerr) = @_;

    if ($key eq 'rootfs') {
        my $res = $parse_ct_mountpoint_full->($class, $rootfs_desc, $volume_string, $noerr);
        $res->{mp} = '/' if defined($res);
        return $res;
    } elsif ($key =~ m/^mp\d+$/) {
        return $parse_ct_mountpoint_full->($class, $mp_desc, $volume_string, $noerr);
    } elsif ($key =~ m/^unused\d+$/) {
        return $parse_ct_mountpoint_full->($class, $unused_desc, $volume_string, $noerr);
    }

    die "parse_volume - unknown type: $key\n" if !$noerr;

    return;
}

sub parse_device {
    my ($class, $device_string, $noerr) = @_;

    my $res = eval { PVE::JSONSchema::parse_property_string($dev_desc, $device_string) };
    if ($@) {
        return undef if $noerr;
        die $@;
    }

    if (!defined($res->{path})) {
        return undef if $noerr;
        die "Path has to be defined\n";
    }

    return $res;
}

sub print_volume {
    my ($class, $key, $volume) = @_;

    return $class->print_ct_unused($volume) if $key =~ m/^unused(\d+)$/;

    return $class->print_ct_mountpoint($volume, $key eq 'rootfs');
}

sub print_device {
    my ($class, $info) = @_;

    return PVE::JSONSchema::print_property_string($info, $dev_desc);
}

sub volid_key {
    my ($class) = @_;

    return 'volume';
}

sub print_lxc_network {
    my ($class, $net) = @_;
    return PVE::JSONSchema::print_property_string($net, $netconf_desc);
}

sub parse_lxc_network {
    my ($class, $data) = @_;

    return {} if !$data;

    my $res = PVE::JSONSchema::parse_property_string($netconf_desc, $data);

    $res->{type} = 'veth';
    if (!$res->{hwaddr}) {
        my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
        $res->{hwaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
    }

    return $res;
}

sub parse_features {
    my ($class, $data) = @_;
    return {} if !$data;
    return PVE::JSONSchema::parse_property_string($features_desc, $data);
}

sub option_exists {
    my ($class, $name) = @_;

    return defined($confdesc->{$name});
}
# END JSON config code

# takes a max memory value as KiB and returns an tuple with max and high values
sub calculate_memory_constraints {
    my ($memory) = @_;

    return if !defined($memory);

    # cgroup memory usage is limited by the hard 'max' limit (OOM-killer enforced) and the soft
    # 'high' limit (cgroup processes get throttled and put under heavy reclaim pressure).
    my $memory_max = int($memory * 1024 * 1024);
    # Set the high to 1016/1024 (~99.2%) of the 'max' hard limit clamped to 128 MiB max, to scale
    # it for the lower range while having a decent 2^x based rest for 2^y memory configs.
    my $memory_high =
        $memory >= 16 * 1024 ? int(($memory - 128) * 1024 * 1024) : int($memory * 1024 * 1016);

    return ($memory_max, $memory_high);
}

my $LXC_FASTPLUG_OPTIONS = {
    'description' => 1,
    'onboot' => 1,
    'startup' => 1,
    'protection' => 1,
    'hostname' => 1,
    'hookscript' => 1,
    'cores' => 1,
    'tags' => 1,
    'lock' => 1,
};

sub vmconfig_hotplug_pending {
    my ($class, $vmid, $conf, $storecfg, $selection, $errors) = @_;

    my $pid = PVE::LXC::find_lxc_pid($vmid);
    my $rootdir = "/proc/$pid/root";

    my $add_hotplug_error = sub {
        my ($opt, $msg) = @_;
        $errors->{$opt} = "unable to hotplug $opt: $msg";
    };

    foreach my $opt (sort keys %{ $conf->{pending} }) { # add/change
        next if $selection && !$selection->{$opt};
        if ($LXC_FASTPLUG_OPTIONS->{$opt}) {
            $conf->{$opt} = delete $conf->{pending}->{$opt};
        }
    }

    my $cgroup = PVE::LXC::CGroup->new($vmid);

    # There's no separate swap size to configure, there's memory and "total"
    # memory (iow. memory+swap). This means we have to change them together.
    my $hotplug_memory_done;
    my $hotplug_memory = sub {
        my ($new_memory, $new_swap) = @_;

        ($new_memory, my $new_memory_high) = calculate_memory_constraints($new_memory);
        $new_swap = int($new_swap * 1024 * 1024) if defined($new_swap);
        $cgroup->change_memory_limit($new_memory, $new_swap, $new_memory_high);

        $hotplug_memory_done = 1;
    };

    my $pending_delete_hash = $class->parse_pending_delete($conf->{pending}->{delete});
    # FIXME: $force deletion is not implemented for CTs
    foreach my $opt (sort keys %$pending_delete_hash) {
        next if $selection && !$selection->{$opt};
        eval {
            if ($LXC_FASTPLUG_OPTIONS->{$opt}) {
                # pass
            } elsif ($opt =~ m/^unused(\d+)$/) {
                PVE::LXC::delete_mountpoint_volume($storecfg, $vmid, $conf->{$opt})
                    if !$class->is_volume_in_use($conf, $conf->{$opt}, 1, 1);
            } elsif ($opt eq 'swap') {
                $hotplug_memory->(undef, 0);
            } elsif ($opt eq 'cpulimit') {
                $cgroup->change_cpu_quota(undef, undef); # reset, cgroup module can better decide values
            } elsif ($opt eq 'cpuunits') {
                $cgroup->change_cpu_shares(undef);
            } elsif ($opt =~ m/^net(\d)$/) {
                my $netid = $1;
                my $net = parse_lxc_network($conf->{$opt});
                PVE::LXC::kill_dhclients($vmid, $net->{name}) if $conf->{ipmanagehost};

                PVE::Network::veth_delete("veth${vmid}i$netid");
                if ($have_sdn) {
                    print "delete ips from $opt\n";
                    eval {
                        PVE::Network::SDN::Vnets::del_ips_from_mac(
                            $net->{bridge},
                            $net->{hwaddr},
                            $conf->{hostname},
                        );
                    };
                    warn $@ if $@;
                }
            } else {
                die "skip\n"; # skip non-hotpluggable opts
            }
        };
        if (my $err = $@) {
            $add_hotplug_error->($opt, $err) if $err ne "skip\n";
        } else {
            delete $conf->{$opt};
            $class->remove_from_pending_delete($conf, $opt);
        }
    }

    foreach my $opt (sort keys %{ $conf->{pending} }) {
        next if $opt eq 'delete'; # just to be sure
        next if $selection && !$selection->{$opt};
        my $value = $conf->{pending}->{$opt};
        eval {
            if ($opt eq 'cpulimit') {
                my $quota = 100000 * $value;
                $cgroup->change_cpu_quota(int(100000 * $value), 100000);
            } elsif ($opt eq 'cpuunits') {
                $cgroup->change_cpu_shares($value);
            } elsif ($opt =~ m/^net(\d+)$/) {
                my $netid = $1;
                my $net = $class->parse_lxc_network($value);
                $value = $class->print_lxc_network($net);
                PVE::LXC::update_net($vmid, $conf, $opt, $net, $netid, $rootdir);
            } elsif ($opt eq 'memory' || $opt eq 'swap') {
                if (!$hotplug_memory_done) { # don't call twice if both opts are passed
                    $hotplug_memory->($conf->{pending}->{memory}, $conf->{pending}->{swap});
                }
            } elsif ($opt =~ m/^mp(\d+)$/) {
                if (exists($conf->{$opt})) {
                    die "skip\n"; # don't try to hotplug over existing mp
                }

                $class->apply_pending_mountpoint($vmid, $conf, $opt, $storecfg, 1);
                # apply_pending_mountpoint modifies the value if it creates a new disk
                $value = $conf->{pending}->{$opt};
            } elsif ($opt =~ m/^dev(\d+)$/) {
                if (exists($conf->{$opt})) {
                    die "skip\n"; # don't try to hotplug over existing dev
                }

                my $dev = $class->parse_device($value);
                PVE::LXC::device_passthrough_hotplug($vmid, $conf, $dev);
            } else {
                die "skip\n"; # skip non-hotpluggable
            }
        };
        if (my $err = $@) {
            $add_hotplug_error->($opt, $err) if $err ne "skip\n";
        } else {
            $conf->{$opt} = $value;
            delete $conf->{pending}->{$opt};
        }
    }
}

sub vmconfig_apply_pending {
    my ($class, $vmid, $conf, $storecfg, $selection, $errors) = @_;

    my $add_apply_error = sub {
        my ($opt, $msg) = @_;
        my $err_msg = "unable to apply pending change $opt : $msg";
        $errors->{$opt} = $err_msg;
        warn $err_msg;
    };

    my $pending_delete_hash = $class->parse_pending_delete($conf->{pending}->{delete});
    # FIXME: $force deletion is not implemented for CTs
    foreach my $opt (sort keys %$pending_delete_hash) {
        next if $selection && !$selection->{$opt};
        eval {
            if ($opt =~ m/^mp(\d+)$/) {
                my $mp = $class->parse_volume($opt, $conf->{$opt});
                if ($mp->{type} eq 'volume') {
                    $class->add_unused_volume($conf, $mp->{volume})
                        if !$class->is_volume_in_use($conf, $conf->{$opt}, 1, 1);
                }
            } elsif ($opt =~ m/^unused(\d+)$/) {
                PVE::LXC::delete_mountpoint_volume($storecfg, $vmid, $conf->{$opt})
                    if !$class->is_volume_in_use($conf, $conf->{$opt}, 1, 1);
            } elsif ($opt =~ m/^net(\d+)$/) {
                if ($have_sdn) {
                    my $net = $class->parse_lxc_network($conf->{$opt});
                    eval {
                        PVE::Network::SDN::Vnets::del_ips_from_mac(
                            $net->{bridge},
                            $net->{hwaddr},
                            $conf->{hostname},
                        );
                    };
                    warn $@ if $@;
                }
            }
        };
        if (my $err = $@) {
            $add_apply_error->($opt, $err);
        } else {
            delete $conf->{$opt};
            $class->remove_from_pending_delete($conf, $opt);
        }
    }

    $class->cleanup_pending($conf);

    foreach my $opt (sort keys %{ $conf->{pending} }) { # add/change
        next if $opt eq 'delete'; # just to be sure
        next if $selection && !$selection->{$opt};
        eval {
            if ($opt =~ m/^mp(\d+)$/) {
                $class->apply_pending_mountpoint($vmid, $conf, $opt, $storecfg, 0);
            } elsif ($opt =~ m/^net(\d+)$/) {
                my $netid = $1;
                my $net = $class->parse_lxc_network($conf->{pending}->{$opt});
                $conf->{pending}->{$opt} = $class->print_lxc_network($net);
                if ($have_sdn) {
                    if ($conf->{$opt}) {
                        my $old_net = $class->parse_lxc_network($conf->{$opt});
                        if (
                            $old_net->{bridge} ne $net->{bridge}
                            || $old_net->{hwaddr} ne $net->{hwaddr}
                        ) {
                            PVE::Network::SDN::Vnets::del_ips_from_mac(
                                $old_net->{bridge},
                                $old_net->{hwaddr},
                                $conf->{name},
                            );
                            PVE::Network::SDN::Vnets::add_next_free_cidr(
                                $net->{bridge},
                                $conf->{hostname},
                                $net->{hwaddr},
                                $vmid,
                                undef,
                                1,
                            );
                        }
                    } else {
                        PVE::Network::SDN::Vnets::add_next_free_cidr(
                            $net->{bridge},
                            $conf->{hostname},
                            $net->{hwaddr},
                            $vmid,
                            undef,
                            1,
                        );
                    }
                }
            }
        };
        if (my $err = $@) {
            $add_apply_error->($opt, $err);
        } else {
            $conf->{$opt} = delete $conf->{pending}->{$opt};
        }
    }
}

my $rescan_volume = sub {
    my ($storecfg, $mp) = @_;
    eval { $mp->{size} = PVE::Storage::volume_size_info($storecfg, $mp->{volume}, 5); };
    warn "Could not rescan volume size - $@\n" if $@;
};

sub apply_pending_mountpoint {
    my ($class, $vmid, $conf, $opt, $storecfg, $running) = @_;

    my $mp = $class->parse_volume($opt, $conf->{pending}->{$opt});
    my $old = $conf->{$opt};
    if ($mp->{type} eq 'volume' && $mp->{volume} =~ $PVE::LXC::NEW_DISK_RE) {
        my $original_value = $conf->{pending}->{$opt};
        my $vollist = PVE::LXC::create_disks(
            $storecfg, $vmid, { $opt => $original_value }, $conf, 1,
        );
        if ($running) {
            # Re-parse mount point:
            my $mp = $class->parse_volume($opt, $conf->{pending}->{$opt});
            eval { PVE::LXC::mountpoint_hotplug($vmid, $conf, $opt, $mp, $storecfg); };
            my $err = $@;
            if ($err) {
                PVE::LXC::destroy_disks($storecfg, $vollist);
                # The pending-changes code collects errors but keeps on looping through further
                # pending changes, so unroll the change in $conf as well if destroy_disks()
                # didn't die().
                $conf->{pending}->{$opt} = $original_value;
                die $err;
            }
        }
    } else {
        die "skip\n" if $running && defined($old); # TODO: "changing" mount points?
        $rescan_volume->($storecfg, $mp) if $mp->{type} eq 'volume';
        if ($running) {
            PVE::LXC::mountpoint_hotplug($vmid, $conf, $opt, $mp, $storecfg);
        }
        $conf->{pending}->{$opt} = $class->print_ct_mountpoint($mp);
    }

    if (defined($old)) {
        my $mp = $class->parse_volume($opt, $old);
        if ($mp->{type} eq 'volume') {
            $class->add_unused_volume($conf, $mp->{volume})
                if !$class->is_volume_in_use($conf, $conf->{$opt}, 1, 1);
        }
    }
}

sub classify_mountpoint {
    my ($class, $vol) = @_;
    if ($vol =~ m!^/!) {
        return 'device' if $vol =~ m!^/dev/!;
        return 'bind';
    }
    return 'volume';
}

my $__is_volume_in_use = sub {
    my ($class, $config, $volid) = @_;
    my $used = 0;

    $class->foreach_volume(
        $config,
        sub {
            my ($ms, $mountpoint) = @_;
            return if $used;
            $used = $mountpoint->{type} eq 'volume' && $mountpoint->{volume} eq $volid;
        },
    );

    return $used;
};

sub is_volume_in_use_by_snapshots {
    my ($class, $config, $volid) = @_;

    if (my $snapshots = $config->{snapshots}) {
        foreach my $snap (keys %$snapshots) {
            return 1 if $__is_volume_in_use->($class, $snapshots->{$snap}, $volid);
        }
    }

    return 0;
}

sub is_volume_in_use {
    my ($class, $config, $volid, $include_snapshots, $include_pending) = @_;
    return 1 if $__is_volume_in_use->($class, $config, $volid);
    return 1 if $include_snapshots && $class->is_volume_in_use_by_snapshots($config, $volid);
    return 1 if $include_pending && $__is_volume_in_use->($class, $config->{pending}, $volid);
    return 0;
}

sub has_dev_console {
    my ($class, $conf) = @_;

    return !(defined($conf->{console}) && !$conf->{console});
}

sub has_lxc_entry {
    my ($class, $conf, $keyname) = @_;

    if (my $lxcconf = $conf->{lxc}) {
        foreach my $entry (@$lxcconf) {
            my ($key, undef) = @$entry;
            return 1 if $key eq $keyname;
        }
    }

    return 0;
}

sub get_tty_count {
    my ($class, $conf) = @_;

    return $conf->{tty} // $confdesc->{tty}->{default};
}

sub get_cmode {
    my ($class, $conf) = @_;

    return $conf->{cmode} // $confdesc->{cmode}->{default};
}

sub get_entrypoint {
    my ($class, $conf) = @_;

    return $conf->{entrypoint} // $confdesc->{entrypoint}->{default};
}

sub valid_volume_keys {
    my ($class, $reverse) = @_;

    my @names = ('rootfs');

    for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
        push @names, "mp$i";
    }

    return $reverse ? reverse @names : @names;
}

sub valid_volume_keys_with_unused {
    my ($class, $reverse) = @_;
    my @names = $class->valid_volume_keys();
    for (my $i = 0; $i < $MAX_UNUSED_DISKS; $i++) {
        push @names, "unused$i";
    }
    return $reverse ? reverse @names : @names;
}

sub get_vm_volumes {
    my ($class, $conf, $excludes) = @_;

    my $vollist = [];

    $class->foreach_volume(
        $conf,
        sub {
            my ($ms, $mountpoint) = @_;

            return if $excludes && $ms eq $excludes;

            my $volid = $mountpoint->{volume};
            return if !$volid || $mountpoint->{type} ne 'volume';

            my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
            return if !$sid;

            push @$vollist, $volid;
        },
    );

    return $vollist;
}

sub get_replicatable_volumes {
    my ($class, $storecfg, $vmid, $conf, $cleanup, $noerr) = @_;

    my $volhash = {};

    my $test_volid = sub {
        my ($volid, $mountpoint) = @_;

        return if !$volid;

        my $mptype = $mountpoint->{type};
        my $replicate = $mountpoint->{replicate} // 1;

        if ($mptype ne 'volume') {
            # skip bindmounts if replicate = 0 even for cleanup,
            # since bind mounts could not have been replicated ever
            return if !$replicate;
            die "unable to replicate mountpoint type '$mptype'\n";
        }

        my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, $noerr);
        return if !$storeid;

        my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
        return if $scfg->{shared};

        my ($path, $owner, $vtype) = PVE::Storage::path($storecfg, $volid);
        return if !$owner || ($owner != $vmid);

        die "unable to replicate volume '$volid', type '$vtype'\n" if $vtype ne 'images';

        return if !$cleanup && !$replicate;

        if (!PVE::Storage::volume_has_feature($storecfg, 'replicate', $volid)) {
            return if $cleanup || $noerr;
            die "missing replicate feature on volume '$volid'\n";
        }

        $volhash->{$volid} = 1;
    };

    $class->foreach_volume(
        $conf,
        sub {
            my ($ms, $mountpoint) = @_;
            $test_volid->($mountpoint->{volume}, $mountpoint);
        },
    );

    foreach my $snapname (keys %{ $conf->{snapshots} }) {
        my $snap = $conf->{snapshots}->{$snapname};
        $class->foreach_volume(
            $snap,
            sub {
                my ($ms, $mountpoint) = @_;
                $test_volid->($mountpoint->{volume}, $mountpoint);
            },
        );
    }

    # add 'unusedX' volumes to volhash
    foreach my $key (keys %$conf) {
        if ($key =~ m/^unused/) {
            $test_volid->($conf->{$key}, { type => 'volume', replicate => 1 });
        }
    }

    return $volhash;
}

sub get_backup_volumes {
    my ($class, $conf) = @_;

    my $return_volumes = [];

    my $test_mountpoint = sub {
        my ($key, $volume) = @_;

        my ($included, $reason) = $class->mountpoint_backup_enabled($key, $volume);

        push @$return_volumes,
            {
                key => $key,
                included => $included,
                reason => $reason,
                volume_config => $volume,
            };
    };

    PVE::LXC::Config->foreach_volume($conf, $test_mountpoint);

    return $return_volumes;
}

sub get_derived_property {
    my ($class, $conf, $name) = @_;

    if ($name eq 'max-cpu') {
        return $conf->{cpulimit} || $conf->{cores} || 0;
    } elsif ($name eq 'max-memory') {
        return ($conf->{memory} || 512) * 1024 * 1024;
    } else {
        die "unknown derived property - $name\n";
    }
}

sub foreach_passthrough_device {
    my ($class, $conf, $func, @param) = @_;

    for my $key (keys %$conf) {
        next if $key !~ m/^dev(\d+)$/;

        my $device = $class->parse_device($conf->{$key});

        $func->($key, $device, @param);
    }
}

1;
