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

sub mountpoint_backup_enabled {
    my ($class, $mp_key, $mountpoint) = @_;

    return 1 if $mp_key eq 'rootfs';

    return 0 if $mountpoint->{type} ne 'volume';

    return 1 if $mountpoint->{backup};

    return 0;
}

sub has_feature {
    my ($class, $feature, $conf, $storecfg, $snapname, $running, $backup_only) = @_;
    my $err;

    $class->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	return if $err; # skip further test
	return if $backup_only && !$class->mountpoint_backup_enabled($ms, $mountpoint);

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

    return if $snapname eq 'vzdump' &&
	!$class->mountpoint_backup_enabled($ms, $mountpoint);

    PVE::Storage::volume_snapshot($storecfg, $mountpoint->{volume}, $snapname);
}

sub __snapshot_delete_remove_drive {
    my ($class, $snap, $remove_drive) = @_;

    if ($remove_drive eq 'vmstate') {
	die "implement me - saving vmstate\n";
    } else {
	my $value = $snap->{$remove_drive};
	my $mountpoint = $remove_drive eq 'rootfs' ? $class->parse_ct_rootfs($value, 1) : $class->parse_ct_mountpoint($value, 1);
	delete $snap->{$remove_drive};

	$class->add_unused_volume($snap, $mountpoint->{volume})
	    if ($mountpoint->{type} eq 'volume');
    }
}

sub __snapshot_delete_vmstate_file {
    my ($class, $snap, $force) = @_;

    die "implement me - saving vmstate\n";
}

sub __snapshot_delete_vol_snapshot {
    my ($class, $vmid, $ms, $mountpoint, $snapname, $unused) = @_;

    return if $snapname eq 'vzdump' &&
	!$class->mountpoint_backup_enabled($ms, $mountpoint);

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_delete($storecfg, $mountpoint->{volume}, $snapname);
    push @$unused, $mountpoint->{volume};
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

    PVE::LXC::vm_stop($vmid, 1)
	if $class->__snapshot_check_running($vmid);
}

sub __snapshot_rollback_vm_start {
    my ($class, $vmid, $vmstate, $forcemachine);

    die "implement me - save vmstate\n";
}

sub __snapshot_rollback_get_unused {
    my ($class, $conf, $snap) = @_;

    my $unused = [];

    $class->__snapshot_foreach_volume($conf, sub {
	my ($vs, $volume) = @_;

	return if $volume->{type} ne 'volume';

	my $found = 0;
	my $volid = $volume->{volume};

	$class->__snapshot_foreach_volume($snap, sub {
	    my ($ms, $mountpoint) = @_;

	    return if $found;
	    return if ($mountpoint->{type} ne 'volume');

	    $found = 1
		if ($mountpoint->{volume} && $mountpoint->{volume} eq $volid);
	});

	push @$unused, $volid if !$found;
    });

    return $unused;
}

sub __snapshot_foreach_volume {
    my ($class, $conf, $func) = @_;

    $class->foreach_mountpoint($conf, $func);
}

# END implemented abstract methods from PVE::AbstractConfig

# BEGIN JSON config code

cfs_register_file('/lxc/', \&parse_pct_config, \&write_pct_config);

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
    ro => {
	type => 'boolean',
	description => 'Read-only mount point',
	optional => 1,
    },
    quota => {
	type => 'boolean',
	description => 'Enable user quotas inside the container (not supported with zfs subvolumes)',
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
	description => 'Mark this non-volume mount point as available on multiple nodes (see \'nodes\')',
	verbose_description => "Mark this non-volume mount point as available on all nodes.\n\nWARNING: This option does not share the mount point automatically, it assumes it is shared already!",
	optional => 1,
	default => 0,
    },
};

PVE::JSONSchema::register_standard_option('pve-ct-rootfs', {
    type => 'string', format => $rootfs_desc,
    description => "Use volume as container root.",
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pve-lxc-snapshot-name', {
    description => "The name of the snapshot.",
    type => 'string', format => 'pve-configid',
    maxLength => 40,
});

my $confdesc = {
    lock => {
	optional => 1,
	type => 'string',
	description => "Lock/unlock the VM.",
	enum => [qw(migrate backup snapshot rollback)],
    },
    onboot => {
	optional => 1,
	type => 'boolean',
	description => "Specifies whether a VM will be started during system bootup.",
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
	enum => ['amd64', 'i386'],
	description => "OS architecture type.",
	default => 'amd64',
    },
    ostype => {
	optional => 1,
	type => 'string',
	enum => [qw(debian ubuntu centos fedora opensuse archlinux alpine gentoo unmanaged)],
	description => "OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/<ostype>.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.",
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
	description => "The number of cores assigned to the container. A container can use all available cores by default.",
	minimum => 1,
	maximum => 128,
    },
    cpulimit => {
	optional => 1,
	type => 'number',
	description => "Limit of CPU usage.\n\nNOTE: If the computer has 2 CPUs, it has a total of '2' CPU time. Value '0' indicates no CPU limit.",
	minimum => 0,
	maximum => 128,
	default => 0,
    },
    cpuunits => {
	optional => 1,
	type => 'integer',
	description => "CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to the weights of all the other running VMs.\n\nNOTE: You can disable fair-scheduler configuration by setting this to 0.",
	minimum => 0,
	maximum => 500000,
	default => 1024,
    },
    memory => {
	optional => 1,
	type => 'integer',
	description => "Amount of RAM for the VM in MB.",
	minimum => 16,
	default => 512,
    },
    swap => {
	optional => 1,
	type => 'integer',
	description => "Amount of SWAP for the VM in MB.",
	minimum => 0,
	default => 512,
    },
    hostname => {
	optional => 1,
	description => "Set a host name for the container.",
	type => 'string', format => 'dns-name',
	maxLength => 255,
    },
    description => {
	optional => 1,
	type => 'string',
        description => "Container description. Only used on the configuration web interface.",
    },
    searchdomain => {
	optional => 1,
	type => 'string', format => 'dns-name-list',
	description => "Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.",
    },
    nameserver => {
	optional => 1,
	type => 'string', format => 'address-list',
	description => "Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.",
    },
    rootfs => get_standard_option('pve-ct-rootfs'),
    parent => {
	optional => 1,
	type => 'string', format => 'pve-configid',
	maxLength => 40,
	description => "Parent snapshot name. This is used internally, and should not be modified.",
    },
    snaptime => {
	optional => 1,
	description => "Timestamp for snapshots.",
	type => 'integer',
	minimum => 0,
    },
    cmode => {
	optional => 1,
	description => "Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).",
	type => 'string',
	enum => ['shell', 'console', 'tty'],
	default => 'tty',
    },
    protection => {
	optional => 1,
	type => 'boolean',
	description => "Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.",
	default => 0,
    },
    unprivileged => {
	optional => 1,
	type => 'boolean',
	description => "Makes the container run as unprivileged user. (Should not be modified manually.)",
	default => 0,
    },
};

my $valid_lxc_conf_keys = {
    'lxc.apparmor.profile' => 1,
    'lxc.apparmor.allow_incomplete' => 1,
    'lxc.selinux.context' => 1,
    'lxc.include' => 1,
    'lxc.arch' => 1,
    'lxc.uts.name' => 1,
    'lxc.signal.halt' => 1,
    'lxc.signal.reboot' => 1,
    'lxc.signal.stop' => 1,
    'lxc.init.cmd' => 1,
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
    'lxc.rootfs.options' => 'lxc.rootfs.options is not supported' .
                            ', please use mount point options in the "rootfs" key',
    # lxc.cgroup.*
    # lxc.prlimit.*
    'lxc.cap.drop' => 1,
    'lxc.cap.keep' => 1,
    'lxc.seccomp.profile' => 1,
    'lxc.idmap' => 1,
    'lxc.hook.pre-start' => 1,
    'lxc.hook.pre-mount' => 1,
    'lxc.hook.mount' => 1,
    'lxc.hook.start' => 1,
    'lxc.hook.stop' => 1,
    'lxc.hook.post-stop' => 1,
    'lxc.hook.clone' => 1,
    'lxc.hook.destroy' => 1,
    'lxc.log.level' => 1,
    'lxc.log.file' => 1,
    'lxc.start.auto' => 1,
    'lxc.start.delay' => 1,
    'lxc.start.order' => 1,
    'lxc.group' => 1,
    'lxc.environment' => 1,
};

my $deprecated_lxc_conf_keys = {
    # Deprecated (removed with lxc 3.0):
    'lxc.aa_profile'           => 'lxc.apparmor.profile',
    'lxc.aa_allow_incomplete'  => 'lxc.apparmor.allow_incomplete',
    'lxc.console'              => 'lxc.console.path',
    'lxc.devttydir'            => 'lxc.tty.dir',
    'lxc.haltsignal'           => 'lxc.signal.halt',
    'lxc.rebootsignal'         => 'lxc.signal.reboot',
    'lxc.stopsignal'           => 'lxc.signal.stop',
    'lxc.id_map'               => 'lxc.idmap',
    'lxc.init_cmd'             => 'lxc.init.cmd',
    'lxc.loglevel'             => 'lxc.log.level',
    'lxc.logfile'              => 'lxc.log.file',
    'lxc.mount'                => 'lxc.mount.fstab',
    'lxc.network.type'         => 'lxc.net.INDEX.type',
    'lxc.network.flags'        => 'lxc.net.INDEX.flags',
    'lxc.network.link'         => 'lxc.net.INDEX.link',
    'lxc.network.mtu'          => 'lxc.net.INDEX.mtu',
    'lxc.network.name'         => 'lxc.net.INDEX.name',
    'lxc.network.hwaddr'       => 'lxc.net.INDEX.hwaddr',
    'lxc.network.ipv4'         => 'lxc.net.INDEX.ipv4.address',
    'lxc.network.ipv4.gateway' => 'lxc.net.INDEX.ipv4.gateway',
    'lxc.network.ipv6'         => 'lxc.net.INDEX.ipv6.address',
    'lxc.network.ipv6.gateway' => 'lxc.net.INDEX.ipv6.gateway',
    'lxc.network.script.up'    => 'lxc.net.INDEX.script.up',
    'lxc.network.script.down'  => 'lxc.net.INDEX.script.down',
    'lxc.pts'                  => 'lxc.pty.max',
    'lxc.se_context'           => 'lxc.selinux.context',
    'lxc.seccomp'              => 'lxc.seccomp.profile',
    'lxc.tty'                  => 'lxc.tty.max',
    'lxc.utsname'              => 'lxc.uts.name',
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
    return 1 if $key =~ /^lxc\.cgroup\./  # allow all cgroup values
             || $key =~ /^lxc\.prlimit\./ # allow all prlimits
             || $key =~ /^lxc\.net\./;    # allow custom network definitions
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
 	description => 'Name of the network device as seen from inside the container. (lxc.network.name)',
	pattern => '[-_.\w\d]+',
    },
    bridge => {
	type => 'string',
	format_description => 'bridge',
	description => 'Bridge to attach the network device to.',
	pattern => '[-_.\w\d]+',
	optional => 1,
    },
    hwaddr => {
	type => 'string',
	format_description => "XX:XX:XX:XX:XX:XX",
        description => 'The interface MAC address. This is dynamically allocated by default, but you can set that statically if needed, for example to always have the same link-local IPv6 address. (lxc.network.hwaddr)',
	pattern => qr/(?:[a-f0-9]{2}:){5}[a-f0-9]{2}/i,
	optional => 1,
    },
    mtu => {
	type => 'integer',
	description => 'Maximum transfer unit of the interface. (lxc.network.mtu)',
	minimum => 64, # minimum ethernet frame is 64 bytes
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
};
PVE::JSONSchema::register_format('pve-lxc-network', $netconf_desc);

my $MAX_LXC_NETWORKS = 10;
for (my $i = 0; $i < $MAX_LXC_NETWORKS; $i++) {
    $confdesc->{"net$i"} = {
	optional => 1,
	type => 'string', format => $netconf_desc,
	description => "Specifies network interfaces for the container.",
    };
}

PVE::JSONSchema::register_format('pve-lxc-mp-string', \&verify_lxc_mp_string);
sub verify_lxc_mp_string {
    my ($mp, $noerr) = @_;

    # do not allow:
    # /./ or /../
    # /. or /.. at the end
    # ../ at the beginning

    if($mp =~ m@/\.\.?/@ ||
       $mp =~ m@/\.\.?$@ ||
       $mp =~ m@^\.\./@) {
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
	verbose_description => 'Whether to include the mount point in backups '.
			       '(only used for volume mount points).',
	optional => 1,
    },
    mp => {
	type => 'string',
	format => 'pve-lxc-mp-string',
	format_description => 'Path',
	description => 'Path to the mount point as seen from inside the container '.
		       '(must not contain symlinks).',
	verbose_description => "Path to the mount point as seen from inside the container.\n\n".
			       "NOTE: Must not contain any symlinks for security reasons."
    },
};
PVE::JSONSchema::register_format('pve-ct-mountpoint', $mp_desc);

my $unuseddesc = {
    optional => 1,
    type => 'string', format => 'pve-volume-id',
    description => "Reference to unused volumes. This is used internally, and should not be modified manually.",
};

for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"mp$i"} = {
	optional => 1,
	type => 'string', format => $mp_desc,
	description => "Use volume as container mount point.",
	optional => 1,
    };
}

for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"unused$i"} = $unuseddesc;
}

sub parse_pct_config {
    my ($filename, $raw) = @_;

    return undef if !defined($raw);

    my $res = {
	digest => Digest::SHA::sha1_hex($raw),
	snapshots => {},
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

	if ($line =~ m/^\[([a-z][a-z0-9_\-]+)\]\s*$/i) {
	    $section = $1;
	    $conf->{description} = $descr if $descr;
	    $descr = '';
	    $conf = $res->{snapshots}->{$section} = {};
	    next;
	}

	if ($line =~ m/^\#(.*)\s*$/) {
	    $descr .= PVE::Tools::decode_text($1) . "\n";
	    next;
	}

	if ($line =~ m/^(lxc\.[a-z0-9_\-\.]+)(:|\s*=)\s*(.*?)\s*$/) {
	    my $key = $1;
	    my $value = $3;
	    my $validity = is_valid_lxc_conf_key($vmid, $key);
	    if ($validity eq 1) {
		push @{$conf->{lxc}}, [$key, $value];
	    } elsif (my $errmsg = $validity) {
		warn "vm $vmid - $key: $errmsg\n";
	    } else {
		warn "vm $vmid - unable to parse config: $line\n";
	    }
	} elsif ($line =~ m/^(description):\s*(.*\S)\s*$/) {
	    $descr .= PVE::Tools::decode_text($2);
	} elsif ($line =~ m/snapstate:\s*(prepare|delete)\s*$/) {
	    $conf->{snapstate} = $1;
	} elsif ($line =~ m/^([a-z][a-z_]*\d*):\s*(\S.*)\s*$/) {
	    my $key = $1;
	    my $value = $2;
	    eval { $value = PVE::LXC::Config->check_type($key, $value); };
	    warn "vm $vmid - unable to parse value of '$key' - $@" if $@;
	    $conf->{$key} = $value;
	} else {
	    warn "vm $vmid - unable to parse config: $line\n";
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
	    $raw .= '#' .  PVE::Tools::encode_text($cl) . "\n";
	}

	foreach my $key (sort keys %$conf) {
	    next if $key eq 'digest' || $key eq 'description' ||
		    $key eq 'pending' || $key eq 'snapshots' ||
		    $key eq 'snapname' || $key eq 'lxc';
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

    foreach my $snapname (sort keys %{$conf->{snapshots}}) {
	$raw .= "\n[$snapname]\n";
	$raw .= &$generate_raw_config($conf->{snapshots}->{$snapname});
    }

    return $raw;
}

sub update_pct_config {
    my ($class, $vmid, $conf, $running, $param, $delete) = @_;

    my @nohotplug;

    my $new_disks = 0;
    my @deleted_volumes;

    my $rootdir;
    if ($running) {
	my $pid = PVE::LXC::find_lxc_pid($vmid);
	$rootdir = "/proc/$pid/root";
    }

    my $hotplug_error = sub {
	if ($running) {
	    push @nohotplug, @_;
	    return 1;
	} else {
	    return 0;
	}
    };

    if (defined($delete)) {
	foreach my $opt (@$delete) {
	    if (!exists($conf->{$opt})) {
		# silently ignore
		next;
	    }

	    if ($opt eq 'memory' || $opt eq 'rootfs') {
		die "unable to delete required option '$opt'\n";
	    } elsif ($opt eq 'hostname') {
		delete $conf->{$opt};
	    } elsif ($opt eq 'swap') {
		delete $conf->{$opt};
		PVE::LXC::write_cgroup_value("memory", $vmid,
					     "memory.memsw.limit_in_bytes", -1);
	    } elsif ($opt eq 'description' || $opt eq 'onboot' || $opt eq 'startup') {
		delete $conf->{$opt};
	    } elsif ($opt eq 'nameserver' || $opt eq 'searchdomain' ||
		     $opt eq 'tty' || $opt eq 'console' || $opt eq 'cmode') {
		next if $hotplug_error->($opt);
		delete $conf->{$opt};
	    } elsif ($opt eq 'cores') {
		delete $conf->{$opt}; # rest is handled by pvestatd
	    } elsif ($opt eq 'cpulimit') {
		PVE::LXC::write_cgroup_value("cpu", $vmid, "cpu.cfs_quota_us", -1);
		delete $conf->{$opt};
	    } elsif ($opt eq 'cpuunits') {
		PVE::LXC::write_cgroup_value("cpu", $vmid, "cpu.shares", $confdesc->{cpuunits}->{default});
		delete $conf->{$opt};
	    } elsif ($opt =~ m/^net(\d)$/) {
		delete $conf->{$opt};
		next if !$running;
		my $netid = $1;
		PVE::Network::veth_delete("veth${vmid}i$netid");
	    } elsif ($opt eq 'protection') {
		delete $conf->{$opt};
	    } elsif ($opt =~ m/^unused(\d+)$/) {
		next if $hotplug_error->($opt);
		PVE::LXC::Config->check_protection($conf, "can't remove CT $vmid drive '$opt'");
		push @deleted_volumes, $conf->{$opt};
		delete $conf->{$opt};
	    } elsif ($opt =~ m/^mp(\d+)$/) {
		next if $hotplug_error->($opt);
		PVE::LXC::Config->check_protection($conf, "can't remove CT $vmid drive '$opt'");
		my $mp = PVE::LXC::Config->parse_ct_mountpoint($conf->{$opt});
		delete $conf->{$opt};
		if ($mp->{type} eq 'volume') {
		    PVE::LXC::Config->add_unused_volume($conf, $mp->{volume});
		}
	    } elsif ($opt eq 'unprivileged') {
		die "unable to delete read-only option: '$opt'\n";
	    } else {
		die "implement me (delete: $opt)"
	    }
	    PVE::LXC::Config->write_config($vmid, $conf) if $running;
	}
    }

    # There's no separate swap size to configure, there's memory and "total"
    # memory (iow. memory+swap). This means we have to change them together.
    my $wanted_memory = PVE::Tools::extract_param($param, 'memory');
    my $wanted_swap =  PVE::Tools::extract_param($param, 'swap');
    if (defined($wanted_memory) || defined($wanted_swap)) {

	my $old_memory = ($conf->{memory} || 512);
	my $old_swap = ($conf->{swap} || 0);

	$wanted_memory //= $old_memory;
	$wanted_swap //= $old_swap;

	my $total = $wanted_memory + $wanted_swap;
	if ($running) {
	    my $old_total = $old_memory + $old_swap;
	    if ($total > $old_total) {
		PVE::LXC::write_cgroup_value("memory", $vmid,
					     "memory.memsw.limit_in_bytes",
					     int($total*1024*1024));
		PVE::LXC::write_cgroup_value("memory", $vmid,
					     "memory.limit_in_bytes",
					     int($wanted_memory*1024*1024));
	    } else {
		PVE::LXC::write_cgroup_value("memory", $vmid,
					     "memory.limit_in_bytes",
					     int($wanted_memory*1024*1024));
		PVE::LXC::write_cgroup_value("memory", $vmid,
					     "memory.memsw.limit_in_bytes",
					     int($total*1024*1024));
	    }
	}
	$conf->{memory} = $wanted_memory;
	$conf->{swap} = $wanted_swap;

	PVE::LXC::Config->write_config($vmid, $conf) if $running;
    }

    my $storecfg = PVE::Storage::config();

    my $used_volids = {};
    my $check_content_type = sub {
	my ($mp) = @_;
	my $sid = PVE::Storage::parse_volume_id($mp->{volume});
	my $storage_config = PVE::Storage::storage_config($storecfg, $sid);
	die "storage '$sid' does not allow content type 'rootdir' (Container)\n"
	    if !$storage_config->{content}->{rootdir};
    };

    my $rescan_volume = sub {
	my ($mp) = @_;
	eval {
	    $mp->{size} = PVE::Storage::volume_size_info($storecfg, $mp->{volume}, 5)
		if !defined($mp->{size});
	};
	warn "Could not rescan volume size - $@\n" if $@;
    };

    foreach my $opt (keys %$param) {
	my $value = $param->{$opt};
	my $check_protection_msg = "can't update CT $vmid drive '$opt'";
	if ($opt eq 'hostname' || $opt eq 'arch') {
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'onboot') {
	    $conf->{$opt} = $value ? 1 : 0;
	} elsif ($opt eq 'startup') {
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'tty' || $opt eq 'console' || $opt eq 'cmode') {
	    next if $hotplug_error->($opt);
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'nameserver') {
	    next if $hotplug_error->($opt);
	    my $list = PVE::LXC::verify_nameserver_list($value);
	    $conf->{$opt} = $list;
	} elsif ($opt eq 'searchdomain') {
	    next if $hotplug_error->($opt);
	    my $list = PVE::LXC::verify_searchdomain_list($value);
	    $conf->{$opt} = $list;
	} elsif ($opt eq 'cores') {
	    $conf->{$opt} = $value;# rest is handled by pvestatd
	} elsif ($opt eq 'cpulimit') {
	    if ($value == 0) {
		PVE::LXC::write_cgroup_value("cpu", $vmid, "cpu.cfs_quota_us", -1);
	    } else {
		PVE::LXC::write_cgroup_value("cpu", $vmid, "cpu.cfs_quota_us", int(100000*$value));
	    }
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'cpuunits') {
	    $conf->{$opt} = $value;
	    PVE::LXC::write_cgroup_value("cpu", $vmid, "cpu.shares", $value);
	} elsif ($opt eq 'description') {
	    $conf->{$opt} = $value;
	} elsif ($opt =~ m/^net(\d+)$/) {
	    my $netid = $1;
	    my $net = PVE::LXC::Config->parse_lxc_network($value);
	    if (!$running) {
		$conf->{$opt} = PVE::LXC::Config->print_lxc_network($net);
	    } else {
		PVE::LXC::update_net($vmid, $conf, $opt, $net, $netid, $rootdir);
	    }
	} elsif ($opt eq 'protection') {
	    $conf->{$opt} = $value ? 1 : 0;
	} elsif ($opt =~ m/^mp(\d+)$/) {
	    next if $hotplug_error->($opt);
	    PVE::LXC::Config->check_protection($conf, $check_protection_msg);
	    my $old = $conf->{$opt};
	    my $mp = PVE::LXC::Config->parse_ct_mountpoint($value);
	    if ($mp->{type} eq 'volume') {
		&$check_content_type($mp);
		$used_volids->{$mp->{volume}} = 1;
		&$rescan_volume($mp);
		$conf->{$opt} = PVE::LXC::Config->print_ct_mountpoint($mp);
	    } else {
		$conf->{$opt} = $value;
	    }
	    if (defined($old)) {
		my $mp = PVE::LXC::Config->parse_ct_mountpoint($old);
		if ($mp->{type} eq 'volume') {
		    PVE::LXC::Config->add_unused_volume($conf, $mp->{volume});
		}
	    }
	    $new_disks = 1;
	} elsif ($opt eq 'rootfs') {
	    next if $hotplug_error->($opt);
	    PVE::LXC::Config->check_protection($conf, $check_protection_msg);
	    my $old = $conf->{$opt};
	    my $mp = PVE::LXC::Config->parse_ct_rootfs($value);
	    if ($mp->{type} eq 'volume') {
		&$check_content_type($mp);
		$used_volids->{$mp->{volume}} = 1;
		&$rescan_volume($mp);
		$conf->{$opt} = PVE::LXC::Config->print_ct_mountpoint($mp, 1);
	    } else {
		$conf->{$opt} = $value;
	    }
	    if (defined($old)) {
		my $mp = PVE::LXC::Config->parse_ct_rootfs($old);
		if ($mp->{type} eq 'volume') {
		    PVE::LXC::Config->add_unused_volume($conf, $mp->{volume});
		}
	    }
	    $new_disks = 1;
	} elsif ($opt eq 'unprivileged') {
	    die "unable to modify read-only option: '$opt'\n";
	} elsif ($opt eq 'ostype') {
	    next if $hotplug_error->($opt);
	    $conf->{$opt} = $value;
	} else {
	    die "implement me: $opt";
	}

	PVE::LXC::Config->write_config($vmid, $conf) if $running;
    }

    # Apply deletions and creations of new volumes
    if (@deleted_volumes) {
	my $storage_cfg = PVE::Storage::config();
	foreach my $volume (@deleted_volumes) {
	    next if $used_volids->{$volume}; # could have been re-added, too
	    # also check for references in snapshots
	    next if $class->is_volume_in_use($conf, $volume, 1);
	    PVE::LXC::delete_mountpoint_volume($storage_cfg, $vmid, $volume);
	}
    }

    if ($new_disks) {
	my $storage_cfg = PVE::Storage::config();
	PVE::LXC::create_disks($storage_cfg, $vmid, $conf, $conf);
    }

    # This should be the last thing we do here
    if ($running && scalar(@nohotplug)) {
	die "unable to modify " . join(',', @nohotplug) . " while container is running\n";
    }
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
	die "internal error"
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

sub __parse_ct_mountpoint_full {
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

sub parse_ct_rootfs {
    my ($class, $data, $noerr) = @_;

    my $res =  $class->__parse_ct_mountpoint_full($rootfs_desc, $data, $noerr);

    $res->{mp} = '/' if defined($res);

    return $res;
}

sub parse_ct_mountpoint {
    my ($class, $data, $noerr) = @_;

    return $class->__parse_ct_mountpoint_full($mp_desc, $data, $noerr);
}

sub print_ct_mountpoint {
    my ($class, $info, $nomp) = @_;
    my $skip = [ 'type' ];
    push @$skip, 'mp' if $nomp;
    return PVE::JSONSchema::print_property_string($info, $mp_desc, $skip);
}

sub print_lxc_network {
    my ($class, $net) = @_;
    return PVE::JSONSchema::print_property_string($net, $netconf_desc);
}

sub parse_lxc_network {
    my ($class, $data) = @_;

    my $res = {};

    return $res if !$data;

    $res = PVE::JSONSchema::parse_property_string($netconf_desc, $data);

    $res->{type} = 'veth';
    if (!$res->{hwaddr}) {
	my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
	$res->{hwaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
    }

    return $res;
}

sub option_exists {
    my ($class, $name) = @_;

    return defined($confdesc->{$name});
}
# END JSON config code

sub classify_mountpoint {
    my ($class, $vol) = @_;
    if ($vol =~ m!^/!) {
	return 'device' if $vol =~ m!^/dev/!;
	return 'bind';
    }
    return 'volume';
}

my $is_volume_in_use = sub {
    my ($class, $config, $volid) = @_;
    my $used = 0;

    $class->foreach_mountpoint($config, sub {
	my ($ms, $mountpoint) = @_;
	return if $used;
	$used = $mountpoint->{type} eq 'volume' && $mountpoint->{volume} eq $volid;
    });

    return $used;
};

sub is_volume_in_use_by_snapshots {
    my ($class, $config, $volid) = @_;

    if (my $snapshots = $config->{snapshots}) {
	foreach my $snap (keys %$snapshots) {
	    return 1 if $is_volume_in_use->($class, $snapshots->{$snap}, $volid);
	}
    }

    return 0;
};

sub is_volume_in_use {
    my ($class, $config, $volid, $include_snapshots) = @_;
    return 1 if $is_volume_in_use->($class, $config, $volid);
    return 1 if $include_snapshots && $class->is_volume_in_use_by_snapshots($config, $volid);
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

sub mountpoint_names {
    my ($class, $reverse) = @_;

    my @names = ('rootfs');

    for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
	push @names, "mp$i";
    }

    return $reverse ? reverse @names : @names;
}

sub foreach_mountpoint_full {
    my ($class, $conf, $reverse, $func, @param) = @_;

    foreach my $key ($class->mountpoint_names($reverse)) {
	my $value = $conf->{$key};
	next if !defined($value);
	my $mountpoint = $key eq 'rootfs' ? $class->parse_ct_rootfs($value, 1) : $class->parse_ct_mountpoint($value, 1);
	next if !defined($mountpoint);

	&$func($key, $mountpoint, @param);
    }
}

sub foreach_mountpoint {
    my ($class, $conf, $func, @param) = @_;

    $class->foreach_mountpoint_full($conf, 0, $func, @param);
}

sub foreach_mountpoint_reverse {
    my ($class, $conf, $func, @param) = @_;

    $class->foreach_mountpoint_full($conf, 1, $func, @param);
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

    $class->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;
	$test_volid->($mountpoint->{volume}, $mountpoint);
    });

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	my $snap = $conf->{snapshots}->{$snapname};
	$class->foreach_mountpoint($snap, sub {
	    my ($ms, $mountpoint) = @_;
	    $test_volid->($mountpoint->{volume}, $mountpoint);
        });
    }

    # add 'unusedX' volumes to volhash
    foreach my $key (keys %$conf) {
	if ($key =~ m/^unused/) {
	    $test_volid->($conf->{$key}, { type => 'volume', replicate => 1 });
	}
    }

    return $volhash;
}

1;
