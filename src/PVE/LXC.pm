package PVE::LXC;

use strict;
use warnings;
use POSIX qw(EINTR);

use File::Path;
use File::Spec;
use Cwd qw();
use Fcntl ':flock';

use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::Storage;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw($IPV6RE $IPV4RE dir_glob_foreach);
use PVE::Network;
use PVE::AccessControl;
use PVE::ProcFSTools;
use Time::HiRes qw (gettimeofday);

use Data::Dumper;

my $nodename = PVE::INotify::nodename();

my $cpuinfo= PVE::ProcFSTools::read_cpuinfo();

our $COMMON_TAR_FLAGS = [ '--sparse', '--numeric-owner', '--acls',
                          '--xattrs',
                          '--xattrs-include=user.*',
                          '--xattrs-include=security.capability',
                          '--warning=no-xattr-write' ];

cfs_register_file('/lxc/', \&parse_pct_config, \&write_pct_config);

my $rootfs_desc = {
    volume => {
	type => 'string',
	default_key => 1,
	format => 'pve-lxc-mp-string',
	format_description => 'volume',
	description => 'Volume, device or directory to mount into the container.',
    },
    backup => {
	type => 'boolean',
	format_description => '[1|0]',
	description => 'Whether to include the mountpoint in backups.',
	optional => 1,
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
	format_description => 'acl',
	description => 'Explicitly enable or disable ACL support.',
	optional => 1,
    },
    ro => {
	type => 'boolean',
	format_description => 'ro',
	description => 'Read-only mountpoint (not supported with bind mounts)',
	optional => 1,
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
	enum => ['debian', 'ubuntu', 'centos', 'fedora', 'opensuse', 'archlinux'],
	description => "OS type. Corresponds to lxc setup scripts in /usr/share/lxc/config/<ostype>.common.conf.",
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
    cpulimit => {
	optional => 1,
	type => 'number',
	description => "Limit of CPU usage. Note if the computer has 2 CPUs, it has a total of '2' CPU time. Value '0' indicates no CPU limit.",
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
    'lxc.include' => 1,
    'lxc.arch' => 1,
    'lxc.utsname' => 1,
    'lxc.haltsignal' => 1,
    'lxc.rebootsignal' => 1,
    'lxc.stopsignal' => 1,
    'lxc.init_cmd' => 1,
    'lxc.network.type' => 1,
    'lxc.network.flags' => 1,
    'lxc.network.link' => 1,
    'lxc.network.mtu' => 1,
    'lxc.network.name' => 1,
    'lxc.network.hwaddr' => 1,
    'lxc.network.ipv4' => 1,
    'lxc.network.ipv4.gateway' => 1,
    'lxc.network.ipv6' => 1,
    'lxc.network.ipv6.gateway' => 1,
    'lxc.network.script.up' => 1,
    'lxc.network.script.down' => 1,
    'lxc.pts' => 1,
    'lxc.console.logfile' => 1,
    'lxc.console' => 1,
    'lxc.tty' => 1,
    'lxc.devttydir' => 1,
    'lxc.hook.autodev' => 1,
    'lxc.autodev' => 1,
    'lxc.kmsg' => 1,
    'lxc.mount' => 1,
    'lxc.mount.entry' => 1,
    'lxc.mount.auto' => 1,
    'lxc.rootfs' => 'lxc.rootfs is auto generated from rootfs',
    'lxc.rootfs.mount' => 1,
    'lxc.rootfs.options' => 'lxc.rootfs.options is not supported' .
                            ', please use mountpoint options in the "rootfs" key',
    # lxc.cgroup.*
    'lxc.cap.drop' => 1,
    'lxc.cap.keep' => 1,
    'lxc.aa_profile' => 1,
    'lxc.aa_allow_incomplete' => 1,
    'lxc.se_context' => 1,
    'lxc.seccomp' => 1,
    'lxc.id_map' => 1,
    'lxc.hook.pre-start' => 1,
    'lxc.hook.pre-mount' => 1,
    'lxc.hook.mount' => 1,
    'lxc.hook.start' => 1,
    'lxc.hook.stop' => 1,
    'lxc.hook.post-stop' => 1,
    'lxc.hook.clone' => 1,
    'lxc.hook.destroy' => 1,
    'lxc.loglevel' => 1,
    'lxc.logfile' => 1,
    'lxc.start.auto' => 1,
    'lxc.start.delay' => 1,
    'lxc.start.order' => 1,
    'lxc.group' => 1,
    'lxc.environment' => 1,
};

my $netconf_desc = {
    type => {
	type => 'string',
	optional => 1,
	description => "Network interface type.",
	enum => [qw(veth)],
    },
    name => {
	type => 'string',
	format_description => 'String',
	description => 'Name of the network device as seen from inside the container. (lxc.network.name)',
	pattern => '[-_.\w\d]+',
    },
    bridge => {
	type => 'string',
	format_description => 'vmbr<Number>',
	description => 'Bridge to attach the network device to.',
	pattern => '[-_.\w\d]+',
	optional => 1,
    },
    hwaddr => {
	type => 'string',
	format_description => 'MAC',
	description => 'Bridge to attach the network device to. (lxc.network.hwaddr)',
	pattern => qr/(?:[a-f0-9]{2}:){5}[a-f0-9]{2}/i,
	optional => 1,
    },
    mtu => {
	type => 'integer',
	format_description => 'Number',
	description => 'Maximum transfer unit of the interface. (lxc.network.mtu)',
	minimum => 64, # minimum ethernet frame is 64 bytes
	optional => 1,
    },
    ip => {
	type => 'string',
	format => 'pve-ipv4-config',
	format_description => 'IPv4Format/CIDR',
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
	format_description => 'IPv6Format/CIDR',
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
	format_description => '[1|0]',
	description => "Controls whether this interface's firewall rules should be used.",
	optional => 1,
    },
    tag => {
	type => 'integer',
	format_description => 'VlanNo',
	minimum => '2',
	maximum => '4094',
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
sub verify_lxc_mp_string{
    my ($mp, $noerr) = @_;

    # do not allow:
    # /./ or /../ 
    # /. or /.. at the end
    # ../ at the beginning
    
    if($mp =~ m@/\.\.?/@ ||
       $mp =~ m@/\.\.?$@ ||
       $mp =~ m@^\.\./@){
	return undef if $noerr;
	die "$mp contains illegal character sequences\n";
    }
    return $mp;
}

my $mp_desc = {
    %$rootfs_desc,
    mp => {
	type => 'string',
	format => 'pve-lxc-mp-string',
	format_description => 'Path',
	description => 'Path to the mountpoint as seen from inside the container.',
    },
};
PVE::JSONSchema::register_format('pve-ct-mountpoint', $mp_desc);

my $unuseddesc = {
    optional => 1,
    type => 'string', format => 'pve-volume-id',
    description => "Reference to unused volumes.",
};

my $MAX_MOUNT_POINTS = 10;
for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"mp$i"} = {
	optional => 1,
	type => 'string', format => $mp_desc,
	description => "Use volume as container mount point (experimental feature).",
	optional => 1,
    };
}

my $MAX_UNUSED_DISKS = $MAX_MOUNT_POINTS;
for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"unused$i"} = $unuseddesc;
}

sub write_pct_config {
    my ($filename, $conf) = @_;

    delete $conf->{snapstate}; # just to be sure

    my $generate_raw_config = sub {
	my ($conf) = @_;

	my $raw = '';

	# add description as comment to top of file
	my $descr = $conf->{description} || '';
	foreach my $cl (split(/\n/, $descr)) {
	    $raw .= '#' .  PVE::Tools::encode_text($cl) . "\n";
	}

	foreach my $key (sort keys %$conf) {
	    next if $key eq 'digest' || $key eq 'description' || $key eq 'pending' || 
		$key eq 'snapshots' || $key eq 'snapname' || $key eq 'lxc';
	    my $value = $conf->{$key};
	    die "detected invalid newline inside property '$key'\n" if $value =~ m/\n/;
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

sub check_type {
    my ($key, $value) = @_;

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
	    my $validity = $valid_lxc_conf_keys->{$key} || 0;
	    if ($validity eq 1 || $key =~ m/^lxc\.cgroup\./) {
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
	    eval { $value = check_type($key, $value); };
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

sub config_list {
    my $vmlist = PVE::Cluster::get_vmlist();
    my $res = {};
    return $res if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};

    foreach my $vmid (keys %$ids) {
	next if !$vmid; # skip CT0
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	next if !$d->{type} || $d->{type} ne 'lxc';
	$res->{$vmid}->{type} = 'lxc';
    }
    return $res;
}

sub cfs_config_path {
    my ($vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/lxc/$vmid.conf";
}

sub config_file {
    my ($vmid, $node) = @_;

    my $cfspath = cfs_config_path($vmid, $node);
    return "/etc/pve/$cfspath";
}

sub load_config {
    my ($vmid, $node) = @_;

    $node = $nodename if !$node;
    my $cfspath = cfs_config_path($vmid, $node);

    my $conf = PVE::Cluster::cfs_read_file($cfspath);
    die "container $vmid does not exist\n" if !defined($conf);

    return $conf;
}

sub create_config {
    my ($vmid, $conf) = @_;

    my $dir = "/etc/pve/nodes/$nodename/lxc";
    mkdir $dir;

    write_config($vmid, $conf);
}

sub destroy_config {
    my ($vmid) = @_;

    unlink config_file($vmid, $nodename);
}

sub write_config {
    my ($vmid, $conf) = @_;

    my $cfspath = cfs_config_path($vmid);

    PVE::Cluster::cfs_write_file($cfspath, $conf);
}

# flock: we use one file handle per process, so lock file
# can be called multiple times and will succeed for the same process.

my $lock_handles =  {};
my $lockdir = "/run/lock/lxc";

sub lock_filename {
    my ($vmid) = @_;

    return "$lockdir/pve-config-${vmid}.lock";
}

sub lock_aquire {
    my ($vmid, $timeout) = @_;

    $timeout = 10 if !$timeout;
    my $mode = LOCK_EX;

    my $filename = lock_filename($vmid);

    mkdir $lockdir if !-d $lockdir;

    my $lock_func = sub {
	if (!$lock_handles->{$$}->{$filename}) {
	    my $fh = new IO::File(">>$filename") ||
		die "can't open file - $!\n";
	    $lock_handles->{$$}->{$filename} = { fh => $fh, refcount => 0};
	}

	if (!flock($lock_handles->{$$}->{$filename}->{fh}, $mode |LOCK_NB)) {
	    print STDERR "trying to aquire lock...";
	    my $success;
	    while(1) {
		$success = flock($lock_handles->{$$}->{$filename}->{fh}, $mode);
		# try again on EINTR (see bug #273)
		if ($success || ($! != EINTR)) {
		    last;
		}
	    }
	    if (!$success) {
		print STDERR " failed\n";
		die "can't aquire lock - $!\n";
	    }

	    print STDERR " OK\n";
	}
	
	$lock_handles->{$$}->{$filename}->{refcount}++;
    };

    eval { PVE::Tools::run_with_timeout($timeout, $lock_func); };
    my $err = $@;
    if ($err) {
	die "can't lock file '$filename' - $err";
    }
}

sub lock_release {
    my ($vmid) = @_;

    my $filename = lock_filename($vmid);

    if (my $fh = $lock_handles->{$$}->{$filename}->{fh}) {
	my $refcount = --$lock_handles->{$$}->{$filename}->{refcount};
	if ($refcount <= 0) {
	    $lock_handles->{$$}->{$filename} = undef;
	    close ($fh);
	}
    }
}

sub lock_container {
    my ($vmid, $timeout, $code, @param) = @_;

    my $res;

    lock_aquire($vmid, $timeout);
    eval { $res = &$code(@param) };
    my $err = $@;
    lock_release($vmid);

    die $err if $err;

    return $res;
}

sub option_exists {
    my ($name) = @_;

    return defined($confdesc->{$name});
}

# add JSON properties for create and set function
sub json_config_properties {
    my $prop = shift;

    foreach my $opt (keys %$confdesc) {
	next if $opt eq 'parent' || $opt eq 'snaptime';
	next if $prop->{$opt};
	$prop->{$opt} = $confdesc->{$opt};
    }

    return $prop;
}

sub json_config_properties_no_rootfs {
    my $prop = shift;

    foreach my $opt (keys %$confdesc) {
	next if $prop->{$opt};
	next if $opt eq 'parent' || $opt eq 'snaptime' || $opt eq 'rootfs';
	$prop->{$opt} = $confdesc->{$opt};
    }

    return $prop;
}

# container status helpers

sub list_active_containers {

    my $filename = "/proc/net/unix";

    # similar test is used by lcxcontainers.c: list_active_containers
    my $res = {};

    my $fh = IO::File->new ($filename, "r");
    return $res if !$fh;

    while (defined(my $line = <$fh>)) {
 	if ($line =~ m/^[a-f0-9]+:\s\S+\s\S+\s\S+\s\S+\s\S+\s\d+\s(\S+)$/) {
	    my $path = $1;
	    if ($path =~ m!^@/var/lib/lxc/(\d+)/command$!) {
		$res->{$1} = 1;
	    }
	}
    }

    close($fh);

    return $res;
}

# warning: this is slow
sub check_running {
    my ($vmid) = @_;

    my $active_hash = list_active_containers();

    return 1 if defined($active_hash->{$vmid});

    return undef;
}

sub get_container_disk_usage {
    my ($vmid, $pid) = @_;

    return PVE::Tools::df("/proc/$pid/root/", 1);
}

my $last_proc_vmid_stat;

my $parse_cpuacct_stat = sub {
    my ($vmid) = @_;

    my $raw = read_cgroup_value('cpuacct', $vmid, 'cpuacct.stat', 1);

    my $stat = {};

    if ($raw =~ m/^user (\d+)\nsystem (\d+)\n/) {

	$stat->{utime} = $1;
	$stat->{stime} = $2;

    }

    return $stat;
};

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc' }} : config_list();

    my $active_hash = list_active_containers();

    my $cpucount = $cpuinfo->{cpus} || 1;

    my $cdtime = gettimeofday;

    my $uptime = (PVE::ProcFSTools::read_proc_uptime(1))[0];

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};

	eval { $d->{pid} = find_lxc_pid($vmid) if defined($active_hash->{$vmid}); };
	warn $@ if $@; # ignore errors (consider them stopped)

	$d->{status} = $d->{pid} ? 'running' : 'stopped';

	my $cfspath = cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	$d->{name} = $conf->{'hostname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;

	$d->{cpus} = $conf->{cpulimit} || $cpucount;

	if ($d->{pid}) {
	    my $res = get_container_disk_usage($vmid, $d->{pid});
	    $d->{disk} = $res->{used};
	    $d->{maxdisk} = $res->{total};
	} else {
	    $d->{disk} = 0;
	    # use 4GB by default ??
	    if (my $rootfs = $conf->{rootfs}) {
		my $rootinfo = parse_ct_rootfs($rootfs);
		$d->{maxdisk} = int(($rootinfo->{size} || 4)*1024*1024)*1024;
	    } else {
		$d->{maxdisk} = 4*1024*1024*1024;
	    }
	}

	$d->{mem} = 0;
	$d->{swap} = 0;
	$d->{maxmem} = ($conf->{memory}||512)*1024*1024;
	$d->{maxswap} = ($conf->{swap}//0)*1024*1024;

	$d->{uptime} = 0;
	$d->{cpu} = 0;

	$d->{netout} = 0;
	$d->{netin} = 0;

	$d->{diskread} = 0;
	$d->{diskwrite} = 0;

	$d->{template} = is_template($conf);
    }

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};
	my $pid = $d->{pid};

	next if !$pid; # skip stopped CTs

	my $ctime = (stat("/proc/$pid"))[10]; # 10 = ctime
	$d->{uptime} = time - $ctime; # the method lxcfs uses

	$d->{mem} = read_cgroup_value('memory', $vmid, 'memory.usage_in_bytes');
	$d->{swap} = read_cgroup_value('memory', $vmid, 'memory.memsw.usage_in_bytes') - $d->{mem};

	my $blkio_bytes = read_cgroup_value('blkio', $vmid, 'blkio.throttle.io_service_bytes', 1);
	my @bytes = split(/\n/, $blkio_bytes);
	foreach my $byte (@bytes) {
	    if (my ($key, $value) = $byte =~ /(Read|Write)\s+(\d+)/) {
		$d->{diskread} = $2 if $key eq 'Read';
		$d->{diskwrite} = $2 if $key eq 'Write';
	    }
	}

	my $pstat = &$parse_cpuacct_stat($vmid);

	my $used = $pstat->{utime} + $pstat->{stime};

	my $old = $last_proc_vmid_stat->{$vmid};
	if (!$old) {
	    $last_proc_vmid_stat->{$vmid} = {
		time => $cdtime,
		used => $used,
		cpu => 0,
	    };
	    next;
	}

	my $dtime = ($cdtime -  $old->{time}) * $cpucount * $cpuinfo->{user_hz};

	if ($dtime > 1000) {
	    my $dutime = $used -  $old->{used};

	    $d->{cpu} = (($dutime/$dtime)* $cpucount) / $d->{cpus};
	    $last_proc_vmid_stat->{$vmid} = {
		time => $cdtime,
		used => $used,
		cpu => $d->{cpu},
	    };
	} else {
	    $d->{cpu} = $old->{cpu};
	}
    }

    my $netdev = PVE::ProcFSTools::read_proc_net_dev();

    foreach my $dev (keys %$netdev) {
	next if $dev !~ m/^veth([1-9]\d*)i/;
	my $vmid = $1;
	my $d = $list->{$vmid};

	next if !$d;

	$d->{netout} += $netdev->{$dev}->{receive};
	$d->{netin} += $netdev->{$dev}->{transmit};

    }

    return $list;
}

sub classify_mountpoint {
    my ($vol) = @_;
    if ($vol =~ m!^/!) {
	return 'device' if $vol =~ m!^/dev/!;
	return 'bind';
    }
    return 'volume';
}

my $parse_ct_mountpoint_full = sub {
    my ($desc, $data, $noerr) = @_;

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

    $res->{type} = classify_mountpoint($res->{volume});

    return $res;
};

sub parse_ct_rootfs {
    my ($data, $noerr) = @_;

    my $res =  &$parse_ct_mountpoint_full($rootfs_desc, $data, $noerr);

    $res->{mp} = '/' if defined($res);

    return $res;
}

sub parse_ct_mountpoint {
    my ($data, $noerr) = @_;

    return &$parse_ct_mountpoint_full($mp_desc, $data, $noerr);
}

sub print_ct_mountpoint {
    my ($info, $nomp) = @_;
    my $skip = [ 'type' ];
    push @$skip, 'mp' if $nomp;
    return PVE::JSONSchema::print_property_string($info, $mp_desc, $skip);
}

sub print_lxc_network {
    my $net = shift;
    return PVE::JSONSchema::print_property_string($net, $netconf_desc);
}

sub parse_lxc_network {
    my ($data) = @_;

    my $res = {};

    return $res if !$data;

    $res = PVE::JSONSchema::parse_property_string($netconf_desc, $data);

    $res->{type} = 'veth';
    $res->{hwaddr} = PVE::Tools::random_ether_addr() if !$res->{hwaddr};

    return $res;
}

sub read_cgroup_value {
    my ($group, $vmid, $name, $full) = @_;

    my $path = "/sys/fs/cgroup/$group/lxc/$vmid/$name";

    return PVE::Tools::file_get_contents($path) if $full;

    return PVE::Tools::file_read_firstline($path);
}

sub write_cgroup_value {
   my ($group, $vmid, $name, $value) = @_;

   my $path = "/sys/fs/cgroup/$group/lxc/$vmid/$name";
   PVE::ProcFSTools::write_proc_entry($path, $value) if -e $path;

}

sub find_lxc_console_pids {

    my $res = {};

    PVE::Tools::dir_glob_foreach('/proc', '\d+', sub {
	my ($pid) = @_;

	my $cmdline = PVE::Tools::file_read_firstline("/proc/$pid/cmdline");
	return if !$cmdline;

	my @args = split(/\0/, $cmdline);

	# search for lxc-console -n <vmid>
	return if scalar(@args) != 3;
	return if $args[1] ne '-n';
	return if $args[2] !~ m/^\d+$/;
	return if $args[0] !~ m|^(/usr/bin/)?lxc-console$|;

	my $vmid = $args[2];

	push @{$res->{$vmid}}, $pid;
    });

    return $res;
}

sub find_lxc_pid {
    my ($vmid) = @_;

    my $pid = undef;
    my $parser = sub {
        my $line = shift;
        $pid = $1 if $line =~ m/^PID:\s+(\d+)$/;
    };
    PVE::Tools::run_command(['lxc-info', '-n', $vmid, '-p'], outfunc => $parser);

    die "unable to get PID for CT $vmid (not running?)\n" if !$pid;

    return $pid;
}

# Note: we cannot use Net:IP, because that only allows strict
# CIDR networks
sub parse_ipv4_cidr {
    my ($cidr, $noerr) = @_;

    if ($cidr =~ m!^($IPV4RE)(?:/(\d+))$! && ($2 > 7) &&  ($2 <= 32)) {
	return { address => $1, netmask => $PVE::Network::ipv4_reverse_mask->[$2] };
    }

    return undef if $noerr;

    die "unable to parse ipv4 address/mask\n";
}

sub check_lock {
    my ($conf) = @_;

    die "VM is locked ($conf->{'lock'})\n" if $conf->{'lock'};
}

sub check_protection {
    my ($vm_conf, $err_msg) = @_;

    if ($vm_conf->{protection}) {
	die "$err_msg - protection mode enabled\n";
    }
}

sub update_lxc_config {
    my ($storage_cfg, $vmid, $conf) = @_;

    my $dir = "/var/lib/lxc/$vmid";

    if ($conf->{template}) {

	unlink "$dir/config";

	return;
    }

    my $raw = '';

    die "missing 'arch' - internal error" if !$conf->{arch};
    $raw .= "lxc.arch = $conf->{arch}\n";

    my $unprivileged = $conf->{unprivileged};
    my $custom_idmap = grep { $_->[0] eq 'lxc.id_map' } @{$conf->{lxc}};

    my $ostype = $conf->{ostype} || die "missing 'ostype' - internal error";
    if ($ostype =~ /^(?:debian | ubuntu | centos | fedora | opensuse | archlinux)$/x) {
	$raw .= "lxc.include = /usr/share/lxc/config/$ostype.common.conf\n";
	if ($unprivileged || $custom_idmap) {
	    $raw .= "lxc.include = /usr/share/lxc/config/$ostype.userns.conf\n"
	}
    } else {
	die "implement me (ostype $ostype)";
    }

    $raw .= "lxc.monitor.unshare = 1\n";

    # Should we read them from /etc/subuid?
    if ($unprivileged && !$custom_idmap) {
	$raw .= "lxc.id_map = u 0 100000 65536\n";
	$raw .= "lxc.id_map = g 0 100000 65536\n";
    }

    if (!has_dev_console($conf)) {
	$raw .= "lxc.console = none\n";
	$raw .= "lxc.cgroup.devices.deny = c 5:1 rwm\n";
    }

    my $ttycount = get_tty_count($conf);
    $raw .= "lxc.tty = $ttycount\n";

    # some init scripts expect a linux terminal (turnkey).
    $raw .= "lxc.environment = TERM=linux\n";
    
    my $utsname = $conf->{hostname} || "CT$vmid";
    $raw .= "lxc.utsname = $utsname\n";

    my $memory = $conf->{memory} || 512;
    my $swap = $conf->{swap} // 0;

    my $lxcmem = int($memory*1024*1024);
    $raw .= "lxc.cgroup.memory.limit_in_bytes = $lxcmem\n";

    my $lxcswap = int(($memory + $swap)*1024*1024);
    $raw .= "lxc.cgroup.memory.memsw.limit_in_bytes = $lxcswap\n";

    if (my $cpulimit = $conf->{cpulimit}) {
	$raw .= "lxc.cgroup.cpu.cfs_period_us = 100000\n";
	my $value = int(100000*$cpulimit);
	$raw .= "lxc.cgroup.cpu.cfs_quota_us = $value\n";
    }

    my $shares = $conf->{cpuunits} || 1024;
    $raw .= "lxc.cgroup.cpu.shares = $shares\n";

    my $mountpoint = parse_ct_rootfs($conf->{rootfs});

    $raw .= "lxc.rootfs = $dir/rootfs\n";

    my $netcount = 0;
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = parse_lxc_network($conf->{$k});
	$netcount++;
	$raw .= "lxc.network.type = veth\n";
	$raw .= "lxc.network.veth.pair = veth${vmid}i${ind}\n";
	$raw .= "lxc.network.hwaddr = $d->{hwaddr}\n" if defined($d->{hwaddr});
	$raw .= "lxc.network.name = $d->{name}\n" if defined($d->{name});
	$raw .= "lxc.network.mtu = $d->{mtu}\n" if defined($d->{mtu});
    }

    if (my $lxcconf = $conf->{lxc}) {
	foreach my $entry (@$lxcconf) {
	    my ($k, $v) = @$entry;
	    $netcount++ if $k eq 'lxc.network.type';
	    $raw .= "$k = $v\n";
	}
    }

    $raw .= "lxc.network.type = empty\n" if !$netcount;
    
    File::Path::mkpath("$dir/rootfs");

    PVE::Tools::file_set_contents("$dir/config", $raw);
}

# verify and cleanup nameserver list (replace \0 with ' ')
sub verify_nameserver_list {
    my ($nameserver_list) = @_;

    my @list = ();
    foreach my $server (PVE::Tools::split_list($nameserver_list)) {
	PVE::JSONSchema::pve_verify_ip($server);
	push @list, $server;
    }

    return join(' ', @list);
}

sub verify_searchdomain_list {
    my ($searchdomain_list) = @_;

    my @list = ();
    foreach my $server (PVE::Tools::split_list($searchdomain_list)) {
	# todo: should we add checks for valid dns domains?
	push @list, $server;
    }

    return join(' ', @list);
}

sub add_unused_volume {
    my ($config, $volid) = @_;

    my $key;
    for (my $ind = $MAX_UNUSED_DISKS - 1; $ind >= 0; $ind--) {
	my $test = "unused$ind";
	if (my $vid = $config->{$test}) {
	    return if $vid eq $volid; # do not add duplicates
	} else {
	    $key = $test;
	}
    }

    die "Too many unused volumes - please delete them first.\n" if !$key;

    $config->{$key} = $volid;

    return $key;
}

sub update_pct_config {
    my ($vmid, $conf, $running, $param, $delete) = @_;

    my @nohotplug;

    my $new_disks = 0;
    my @deleted_volumes;

    my $rootdir;
    if ($running) {
	my $pid = find_lxc_pid($vmid);
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
		warn "no such option: $opt\n";
		next;
	    }

	    if ($opt eq 'hostname' || $opt eq 'memory' || $opt eq 'rootfs') {
		die "unable to delete required option '$opt'\n";
	    } elsif ($opt eq 'swap') {
		delete $conf->{$opt};
		write_cgroup_value("memory", $vmid, "memory.memsw.limit_in_bytes", -1);
	    } elsif ($opt eq 'description' || $opt eq 'onboot' || $opt eq 'startup') {
		delete $conf->{$opt};
	    } elsif ($opt eq 'nameserver' || $opt eq 'searchdomain' ||
		     $opt eq 'tty' || $opt eq 'console' || $opt eq 'cmode') {
		next if $hotplug_error->($opt);
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
		check_protection($conf, "can't remove CT $vmid drive '$opt'");
		push @deleted_volumes, $conf->{$opt};
		delete $conf->{$opt};
	    } elsif ($opt =~ m/^mp(\d+)$/) {
		next if $hotplug_error->($opt);
		check_protection($conf, "can't remove CT $vmid drive '$opt'");
		my $mountpoint = parse_ct_mountpoint($conf->{$opt});
		if ($mountpoint->{type} eq 'volume') {
		    add_unused_volume($conf, $mountpoint->{volume})
		}
		delete $conf->{$opt};
	    } elsif ($opt eq 'unprivileged') {
		die "unable to delete read-only option: '$opt'\n";
	    } else {
		die "implement me (delete: $opt)"
	    }
	    write_config($vmid, $conf) if $running;
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
		write_cgroup_value("memory", $vmid, "memory.memsw.limit_in_bytes", int($total*1024*1024));
		write_cgroup_value("memory", $vmid, "memory.limit_in_bytes", int($wanted_memory*1024*1024));
	    } else {
		write_cgroup_value("memory", $vmid, "memory.limit_in_bytes", int($wanted_memory*1024*1024));
		write_cgroup_value("memory", $vmid, "memory.memsw.limit_in_bytes", int($total*1024*1024));
	    }
	}
	$conf->{memory} = $wanted_memory;
	$conf->{swap} = $wanted_swap;

	write_config($vmid, $conf) if $running;
    }

    foreach my $opt (keys %$param) {
	my $value = $param->{$opt};
	if ($opt eq 'hostname') {
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
	    my $list = verify_nameserver_list($value);
	    $conf->{$opt} = $list;
	} elsif ($opt eq 'searchdomain') {
	    next if $hotplug_error->($opt);
	    my $list = verify_searchdomain_list($value);
	    $conf->{$opt} = $list;
	} elsif ($opt eq 'cpulimit') {
	    next if $hotplug_error->($opt); # FIXME: hotplug
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'cpuunits') {
	    $conf->{$opt} = $value;
	    write_cgroup_value("cpu", $vmid, "cpu.shares", $value);
	} elsif ($opt eq 'description') {
	    $conf->{$opt} = PVE::Tools::encode_text($value);
	} elsif ($opt =~ m/^net(\d+)$/) {
	    my $netid = $1;
	    my $net = parse_lxc_network($value);
	    if (!$running) {
		$conf->{$opt} = print_lxc_network($net);
	    } else {
		update_net($vmid, $conf, $opt, $net, $netid, $rootdir);
	    }
	} elsif ($opt eq 'protection') {
	    $conf->{$opt} = $value ? 1 : 0;
        } elsif ($opt =~ m/^mp(\d+)$/) {
	    next if $hotplug_error->($opt);
	    check_protection($conf, "can't update CT $vmid drive '$opt'");
	    $conf->{$opt} = $value;
	    $new_disks = 1;
        } elsif ($opt eq 'rootfs') {
	    check_protection($conf, "can't update CT $vmid drive '$opt'");
	    die "implement me: $opt";
	} elsif ($opt eq 'unprivileged') {
	    die "unable to modify read-only option: '$opt'\n";
	} else {
	    die "implement me: $opt";
	}
	write_config($vmid, $conf) if $running;
    }

    if (@deleted_volumes) {
	my $storage_cfg = PVE::Storage::config();
	foreach my $volume (@deleted_volumes) {
	    delete_mountpoint_volume($storage_cfg, $vmid, $volume);
	}
    }

    if ($new_disks) {
	my $storage_cfg = PVE::Storage::config();
	create_disks($storage_cfg, $vmid, $conf, $conf);
    }

    # This should be the last thing we do here
    if ($running && scalar(@nohotplug)) {
	die "unable to modify " . join(',', @nohotplug) . " while container is running\n";
    }
}

sub has_dev_console {
    my ($conf) = @_;

    return !(defined($conf->{console}) && !$conf->{console});
}
	
sub get_tty_count {
    my ($conf) = @_;

    return $conf->{tty} // $confdesc->{tty}->{default};
}

sub get_cmode {
    my ($conf) = @_;

    return $conf->{cmode} // $confdesc->{cmode}->{default};
}

sub get_console_command {
    my ($vmid, $conf) = @_;

    my $cmode = get_cmode($conf);

    if ($cmode eq 'console') {
	return ['lxc-console', '-n',  $vmid, '-t', 0];
    } elsif ($cmode eq 'tty') {
	return ['lxc-console', '-n',  $vmid];
    } elsif ($cmode eq 'shell') {
	return ['lxc-attach', '--clear-env', '-n', $vmid];
    } else {
	die "internal error";
    }
}

sub get_primary_ips {
    my ($conf) = @_;

    # return data from net0

    return undef if !defined($conf->{net0});
    my $net = parse_lxc_network($conf->{net0});

    my $ipv4 = $net->{ip};
    if ($ipv4) {
	if ($ipv4 =~ /^(dhcp|manual)$/) {
	    $ipv4 = undef
	} else {
	    $ipv4 =~ s!/\d+$!!;
	}
    }
    my $ipv6 = $net->{ip6};
    if ($ipv6) {
	if ($ipv6 =~ /^(auto|dhcp|manual)$/) {
	    $ipv6 = undef;
	} else {
	    $ipv6 =~ s!/\d+$!!;
	}
    }

    return ($ipv4, $ipv6);
}

sub delete_mountpoint_volume {
    my ($storage_cfg, $vmid, $volume) = @_;

    return if classify_mountpoint($volume) ne 'volume';

    my ($vtype, $name, $owner) = PVE::Storage::parse_volname($storage_cfg, $volume);
    PVE::Storage::vdisk_free($storage_cfg, $volume) if $vmid == $owner;
}

sub destroy_lxc_container {
    my ($storage_cfg, $vmid, $conf) = @_;

    foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;
	delete_mountpoint_volume($storage_cfg, $vmid, $mountpoint->{volume});
    });

    rmdir "/var/lib/lxc/$vmid/rootfs";
    unlink "/var/lib/lxc/$vmid/config";
    rmdir "/var/lib/lxc/$vmid";
    destroy_config($vmid);

    #my $cmd = ['lxc-destroy', '-n', $vmid ];
    #PVE::Tools::run_command($cmd);
}

sub vm_stop_cleanup {
    my ($storage_cfg, $vmid, $conf, $keepActive) = @_;
    
    eval {
	if (!$keepActive) {

            my $vollist = get_vm_volumes($conf);
	    PVE::Storage::deactivate_volumes($storage_cfg, $vollist);
	}
    };
    warn $@ if $@; # avoid errors - just warn
}

my $safe_num_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a != $b;
};

my $safe_string_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a ne $b;
};

sub update_net {
    my ($vmid, $conf, $opt, $newnet, $netid, $rootdir) = @_;

    if ($newnet->{type} ne 'veth') {
	# for when there are physical interfaces
	die "cannot update interface of type $newnet->{type}";
    }

    my $veth = "veth${vmid}i${netid}";
    my $eth = $newnet->{name};

    if (my $oldnetcfg = $conf->{$opt}) {
	my $oldnet = parse_lxc_network($oldnetcfg);

	if (&$safe_string_ne($oldnet->{hwaddr}, $newnet->{hwaddr}) ||
	    &$safe_string_ne($oldnet->{name}, $newnet->{name})) {

	    PVE::Network::veth_delete($veth);
	    delete $conf->{$opt};
	    write_config($vmid, $conf);

	    hotplug_net($vmid, $conf, $opt, $newnet, $netid);

	} elsif (&$safe_string_ne($oldnet->{bridge}, $newnet->{bridge}) ||
		 &$safe_num_ne($oldnet->{tag}, $newnet->{tag}) ||
		 &$safe_num_ne($oldnet->{firewall}, $newnet->{firewall})) {

		if ($oldnet->{bridge}) {
		    PVE::Network::tap_unplug($veth);
		    foreach (qw(bridge tag firewall)) {
			delete $oldnet->{$_};
		    }
		    $conf->{$opt} = print_lxc_network($oldnet);
		    write_config($vmid, $conf);
		}

		PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall}, $newnet->{trunks});
		foreach (qw(bridge tag firewall)) {
		    $oldnet->{$_} = $newnet->{$_} if $newnet->{$_};
		}
		$conf->{$opt} = print_lxc_network($oldnet);
		write_config($vmid, $conf);
	}
    } else {
	hotplug_net($vmid, $conf, $opt, $newnet, $netid);
    }

    update_ipconfig($vmid, $conf, $opt, $eth, $newnet, $rootdir);
}

sub hotplug_net {
    my ($vmid, $conf, $opt, $newnet, $netid) = @_;

    my $veth = "veth${vmid}i${netid}";
    my $vethpeer = $veth . "p";
    my $eth = $newnet->{name};

    PVE::Network::veth_create($veth, $vethpeer, $newnet->{bridge}, $newnet->{hwaddr});
    PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall}, $newnet->{trunks});

    # attach peer in container
    my $cmd = ['lxc-device', '-n', $vmid, 'add', $vethpeer, "$eth" ];
    PVE::Tools::run_command($cmd);

    # link up peer in container
    $cmd = ['lxc-attach', '-n', $vmid, '-s', 'NETWORK', '--', '/sbin/ip', 'link', 'set', $eth ,'up'  ];
    PVE::Tools::run_command($cmd);

    my $done = { type => 'veth' };
    foreach (qw(bridge tag firewall hwaddr name)) {
	$done->{$_} = $newnet->{$_} if $newnet->{$_};
    }
    $conf->{$opt} = print_lxc_network($done);

    write_config($vmid, $conf);
}

sub update_ipconfig {
    my ($vmid, $conf, $opt, $eth, $newnet, $rootdir) = @_;

    my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir);

    my $optdata = parse_lxc_network($conf->{$opt});
    my $deleted = [];
    my $added = [];
    my $nscmd = sub {
	my $cmdargs = shift;
	PVE::Tools::run_command(['lxc-attach', '-n', $vmid, '-s', 'NETWORK', '--', @_], %$cmdargs);
    };
    my $ipcmd = sub { &$nscmd({}, '/sbin/ip', @_) };

    my $change_ip_config = sub {
	my ($ipversion) = @_;

	my $family_opt = "-$ipversion";
	my $suffix = $ipversion == 4 ? '' : $ipversion;
	my $gw= "gw$suffix";
	my $ip= "ip$suffix";

	my $newip = $newnet->{$ip};
	my $newgw = $newnet->{$gw};
	my $oldip = $optdata->{$ip};

	my $change_ip = &$safe_string_ne($oldip, $newip);
	my $change_gw = &$safe_string_ne($optdata->{$gw}, $newgw);

	return if !$change_ip && !$change_gw;

	# step 1: add new IP, if this fails we cancel
	my $is_real_ip = ($newip && $newip !~ /^(?:auto|dhcp|manual)$/);
	if ($change_ip && $is_real_ip) {
	    eval { &$ipcmd($family_opt, 'addr', 'add', $newip, 'dev', $eth); };
	    if (my $err = $@) {
		warn $err;
		return;
	    }
	}

	# step 2: replace gateway
	#   If this fails we delete the added IP and cancel.
	#   If it succeeds we save the config and delete the old IP, ignoring
	#   errors. The config is then saved.
	# Note: 'ip route replace' can add
	if ($change_gw) {
	    if ($newgw) {
		eval {
		    if ($is_real_ip && !PVE::Network::is_ip_in_cidr($newgw, $newip, $ipversion)) {
			&$ipcmd($family_opt, 'route', 'add', $newgw, 'dev', $eth);
		    }
		    &$ipcmd($family_opt, 'route', 'replace', 'default', 'via', $newgw);
		};
		if (my $err = $@) {
		    warn $err;
		    # the route was not replaced, the old IP is still available
		    # rollback (delete new IP) and cancel
		    if ($change_ip) {
			eval { &$ipcmd($family_opt, 'addr', 'del', $newip, 'dev', $eth); };
			warn $@ if $@; # no need to die here
		    }
		    return;
		}
	    } else {
		eval { &$ipcmd($family_opt, 'route', 'del', 'default'); };
		# if the route was not deleted, the guest might have deleted it manually
		# warn and continue
		warn $@ if $@;
	    }
	}

	# from this point on we save the configuration
	# step 3: delete old IP ignoring errors
	if ($change_ip && $oldip && $oldip !~ /^(?:auto|dhcp)$/) {
	    # We need to enable promote_secondaries, otherwise our newly added
	    # address will be removed along with the old one.
	    my $promote = 0;
	    eval {
		if ($ipversion == 4) {
		    &$nscmd({ outfunc => sub { $promote = int(shift) } },
			    'cat', "/proc/sys/net/ipv4/conf/$eth/promote_secondaries");
		    &$nscmd({}, 'sysctl', "net.ipv4.conf.$eth.promote_secondaries=1");
		}
		&$ipcmd($family_opt, 'addr', 'del', $oldip, 'dev', $eth);
	    };
	    warn $@ if $@; # no need to die here

	    if ($ipversion == 4) {
		&$nscmd({}, 'sysctl', "net.ipv4.conf.$eth.promote_secondaries=$promote");
	    }
	}

	foreach my $property ($ip, $gw) {
	    if ($newnet->{$property}) {
		$optdata->{$property} = $newnet->{$property};
	    } else {
		delete $optdata->{$property};
	    }
	}
	$conf->{$opt} = print_lxc_network($optdata);
	write_config($vmid, $conf);
	$lxc_setup->setup_network($conf);
    };

    &$change_ip_config(4);
    &$change_ip_config(6);

}

# Internal snapshots

# NOTE: Snapshot create/delete involves several non-atomic
# actions, and can take a long time.
# So we try to avoid locking the file and use the 'lock' variable
# inside the config file instead.

my $snapshot_copy_config = sub {
    my ($source, $dest) = @_;

    foreach my $k (keys %$source) {
	next if $k eq 'snapshots';
	next if $k eq 'snapstate';
	next if $k eq 'snaptime';
	next if $k eq 'vmstate';
	next if $k eq 'lock';
	next if $k eq 'digest';
	next if $k eq 'description';

	$dest->{$k} = $source->{$k};
    }
};

my $snapshot_prepare = sub {
    my ($vmid, $snapname, $comment) = @_;

    my $snap;

    my $updatefn =  sub {

	my $conf = load_config($vmid);

	die "you can't take a snapshot if it's a template\n"
	    if is_template($conf);

	check_lock($conf);

	$conf->{lock} = 'snapshot';

	die "snapshot name '$snapname' already used\n"
	    if defined($conf->{snapshots}->{$snapname});

	my $storecfg = PVE::Storage::config();
	my $feature = $snapname eq 'vzdump' ? 'vzdump' : 'snapshot';
	die "snapshot feature is not available\n" if !has_feature($feature, $conf, $storecfg);

	$snap = $conf->{snapshots}->{$snapname} = {};

	&$snapshot_copy_config($conf, $snap);

	$snap->{'snapstate'} = "prepare";
	$snap->{'snaptime'} = time();
	$snap->{'description'} = $comment if $comment;
	$conf->{snapshots}->{$snapname} = $snap;

	write_config($vmid, $conf);
    };

    lock_container($vmid, 10, $updatefn);

    return $snap;
};

my $snapshot_commit = sub {
    my ($vmid, $snapname) = @_;

    my $updatefn = sub {

	my $conf = load_config($vmid);

	die "missing snapshot lock\n"
	    if !($conf->{lock} && $conf->{lock} eq 'snapshot');

	die "snapshot '$snapname' does not exist\n"
	    if !defined($conf->{snapshots}->{$snapname});

	die "wrong snapshot state\n"
	    if !($conf->{snapshots}->{$snapname}->{'snapstate'} && 
		 $conf->{snapshots}->{$snapname}->{'snapstate'} eq "prepare");

	delete $conf->{snapshots}->{$snapname}->{'snapstate'};
	delete $conf->{lock};
	$conf->{parent} = $snapname;

	write_config($vmid, $conf);
    };

    lock_container($vmid, 10 ,$updatefn);
};

sub has_feature {
    my ($feature, $conf, $storecfg, $snapname) = @_;
    
    my $err;
    my $vzdump = $feature eq 'vzdump';
    $feature = 'snapshot' if $vzdump;

    foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	return if $err; # skip further test
	return if $vzdump && $ms ne 'rootfs' && !$mountpoint->{backup};
	
	$err = 1 if !PVE::Storage::volume_has_feature($storecfg, $feature, $mountpoint->{volume}, $snapname);

	# TODO: implement support for mountpoints
	die "unable to handle mountpoint '$ms' - feature not implemented\n"
	    if $ms ne 'rootfs';
    });

    return $err ? 0 : 1;
}

sub snapshot_create {
    my ($vmid, $snapname, $comment) = @_;

    my $snap = &$snapshot_prepare($vmid, $snapname, $comment);

    my $conf = load_config($vmid);

    my $running = check_running($vmid);
    
    my $unfreeze = 0;
    
    eval {
	if ($running) {
	    PVE::Tools::run_command(['/usr/bin/lxc-freeze', '-n', $vmid]);
	    $unfreeze = 1;
	    PVE::Tools::run_command(['/bin/sync']);
	};

	my $storecfg = PVE::Storage::config();
	my $rootinfo = parse_ct_rootfs($conf->{rootfs});
	my $volid = $rootinfo->{volume};

	PVE::Storage::volume_snapshot($storecfg, $volid, $snapname);
	&$snapshot_commit($vmid, $snapname);
    };
    my $err = $@;
    
    if ($unfreeze) {
	eval { PVE::Tools::run_command(['/usr/bin/lxc-unfreeze', '-n', $vmid]); };
	warn $@ if $@;
    }
    
    if ($err) {
	snapshot_delete($vmid, $snapname, 1);
	die "$err\n";
    }
}

sub snapshot_delete {
    my ($vmid, $snapname, $force) = @_;

    my $snap;

    my $conf;

    my $updatefn =  sub {

	$conf = load_config($vmid);

	die "you can't delete a snapshot if vm is a template\n"
	    if is_template($conf);

	$snap = $conf->{snapshots}->{$snapname};

	check_lock($conf);

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	$snap->{snapstate} = 'delete';

	write_config($vmid, $conf);
    };

    lock_container($vmid, 10, $updatefn);

    my $storecfg = PVE::Storage::config();

    my $unlink_parent = sub {

	my ($confref, $new_parent) = @_;

	if ($confref->{parent} && $confref->{parent} eq $snapname) {
	    if ($new_parent) {
		$confref->{parent} = $new_parent;
	    } else {
		delete $confref->{parent};
	    }
	}
    };

    my $del_snap =  sub {

	check_lock($conf);

	my $parent = $conf->{snapshots}->{$snapname}->{parent};
	foreach my $snapkey (keys %{$conf->{snapshots}}) {
	    &$unlink_parent($conf->{snapshots}->{$snapkey}, $parent);
	}

	&$unlink_parent($conf, $parent);

	delete $conf->{snapshots}->{$snapname};

	write_config($vmid, $conf);
    };

    my $rootfs = $conf->{snapshots}->{$snapname}->{rootfs};
    my $rootinfo = parse_ct_rootfs($rootfs);
    my $volid = $rootinfo->{volume};

    eval {
	PVE::Storage::volume_snapshot_delete($storecfg, $volid, $snapname);
    };
    my $err = $@;

    if(!$err || ($err && $force)) {
	lock_container($vmid, 10, $del_snap);
	if ($err) {
	    die "Can't delete snapshot: $vmid $snapname $err\n";
	}
    }
}

sub snapshot_rollback {
    my ($vmid, $snapname) = @_;

    my $storecfg = PVE::Storage::config();

    my $conf = load_config($vmid);

    die "you can't rollback if vm is a template\n" if is_template($conf);

    my $snap = $conf->{snapshots}->{$snapname};

    die "snapshot '$snapname' does not exist\n" if !defined($snap);

    my $rootfs = $snap->{rootfs};
    my $rootinfo = parse_ct_rootfs($rootfs);
    my $volid = $rootinfo->{volume};

    PVE::Storage::volume_rollback_is_possible($storecfg, $volid, $snapname);

    my $updatefn = sub {

	die "unable to rollback to incomplete snapshot (snapstate = $snap->{snapstate})\n" 
	    if $snap->{snapstate};

	check_lock($conf);

	system("lxc-stop -n $vmid --kill") if check_running($vmid);

	die "unable to rollback vm $vmid: vm is running\n"
	    if check_running($vmid);

	$conf->{lock} = 'rollback';

	my $forcemachine;

	# copy snapshot config to current config

	my $tmp_conf = $conf;
	&$snapshot_copy_config($tmp_conf->{snapshots}->{$snapname}, $conf);
	$conf->{snapshots} = $tmp_conf->{snapshots};
	delete $conf->{snaptime};
	delete $conf->{snapname};
	$conf->{parent} = $snapname;

	write_config($vmid, $conf);
    };

    my $unlockfn = sub {
	delete $conf->{lock};
	write_config($vmid, $conf);
    };

    lock_container($vmid, 10, $updatefn);

    PVE::Storage::volume_snapshot_rollback($storecfg, $volid, $snapname);

    lock_container($vmid, 5, $unlockfn);
}

sub template_create {
    my ($vmid, $conf) = @_;

    my $storecfg = PVE::Storage::config();

    my $rootinfo = parse_ct_rootfs($conf->{rootfs});
    my $volid = $rootinfo->{volume};

    die "Template feature is not available for '$volid'\n"
	if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);

    PVE::Storage::activate_volumes($storecfg, [$volid]);

    my $template_volid = PVE::Storage::vdisk_create_base($storecfg, $volid);
    $rootinfo->{volume} = $template_volid;
    $conf->{rootfs} = print_ct_mountpoint($rootinfo, 1);

    write_config($vmid, $conf);
}

sub is_template {
    my ($conf) = @_;

    return 1 if defined $conf->{template} && $conf->{template} == 1;
}

sub mountpoint_names {
    my ($reverse) = @_;

    my @names = ('rootfs');

    for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
	push @names, "mp$i";
    }

    return $reverse ? reverse @names : @names;
}


sub foreach_mountpoint_full {
    my ($conf, $reverse, $func) = @_;

    foreach my $key (mountpoint_names($reverse)) {
	my $value = $conf->{$key};
	next if !defined($value);
	my $mountpoint = $key eq 'rootfs' ? parse_ct_rootfs($value, 1) : parse_ct_mountpoint($value, 1);
	next if !defined($mountpoint);

	&$func($key, $mountpoint);
    }
}

sub foreach_mountpoint {
    my ($conf, $func) = @_;

    foreach_mountpoint_full($conf, 0, $func);
}

sub foreach_mountpoint_reverse {
    my ($conf, $func) = @_;

    foreach_mountpoint_full($conf, 1, $func);
}

sub check_ct_modify_config_perm {
    my ($rpcenv, $authuser, $vmid, $pool, $key_list) = @_;

    return 1 if $authuser ne 'root@pam';

    foreach my $opt (@$key_list) {

	if ($opt eq 'cpus' || $opt eq 'cpuunits' || $opt eq 'cpulimit') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'rootfs' || $opt =~ /^mp\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	} elsif ($opt eq 'memory' || $opt eq 'swap') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt =~ m/^net\d+$/ || $opt eq 'nameserver' ||
		 $opt eq 'searchdomain' || $opt eq 'hostname') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} else {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Options']);
	}
    }

    return 1;
}

sub umount_all {
    my ($vmid, $storage_cfg, $conf, $noerr) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    my $volid_list = get_vm_volumes($conf);

    foreach_mountpoint_reverse($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my $mount = $mountpoint->{mp};

	return if !$volid || !$mount;

	my $mount_path = "$rootdir/$mount";
	$mount_path =~ s!/+!/!g;

	return if !PVE::ProcFSTools::is_mounted($mount_path);

	eval {
	    PVE::Tools::run_command(['umount', '-d', $mount_path]);
	};
	if (my $err = $@) {
	    if ($noerr) {
		warn $err;
	    } else {
		die $err;
	    }
	}
    });
}

sub mount_all {
    my ($vmid, $storage_cfg, $conf) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    File::Path::make_path($rootdir);

    my $volid_list = get_vm_volumes($conf);
    PVE::Storage::activate_volumes($storage_cfg, $volid_list);

    eval {
	foreach_mountpoint($conf, sub {
	    my ($ms, $mountpoint) = @_;

	    mountpoint_mount($mountpoint, $rootdir, $storage_cfg);
        });
    };
    if (my $err = $@) {
	warn "mounting container failed\n";
	umount_all($vmid, $storage_cfg, $conf, 1);
	die $err;
    }

    return $rootdir;
}


sub mountpoint_mount_path {
    my ($mountpoint, $storage_cfg, $snapname) = @_;

    return mountpoint_mount($mountpoint, undef, $storage_cfg, $snapname);
}

my $check_mount_path = sub {
    my ($path) = @_;
    $path = File::Spec->canonpath($path);
    my $real = Cwd::realpath($path);
    if ($real ne $path) {
	die "mount path modified by symlink: $path != $real";
    }
};

sub query_loopdev {
    my ($path) = @_;
    my $found;
    my $parser = sub {
	my $line = shift;
	if ($line =~ m@^(/dev/loop\d+):@) {
	    $found = $1;
	}
    };
    my $cmd = ['losetup', '--associated', $path];
    PVE::Tools::run_command($cmd, outfunc => $parser);
    return $found;
}

# use $rootdir = undef to just return the corresponding mount path
sub mountpoint_mount {
    my ($mountpoint, $rootdir, $storage_cfg, $snapname) = @_;

    my $volid = $mountpoint->{volume};
    my $mount = $mountpoint->{mp};
    my $type = $mountpoint->{type};
    
    return if !$volid || !$mount;

    my $mount_path;
    
    if (defined($rootdir)) {
	$rootdir =~ s!/+$!!;
	$mount_path = "$rootdir/$mount";
	$mount_path =~ s!/+!/!g;
	&$check_mount_path($mount_path);
	File::Path::mkpath($mount_path);
    }
    
    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "unknown snapshot path for '$volid'" if !$storage && defined($snapname);

    my $optstring = '';
    if (defined($mountpoint->{acl})) {
	$optstring .= ($mountpoint->{acl} ? 'acl' : 'noacl');
    }
    if ($mountpoint->{ro}) {
	$optstring .= ',' if $optstring;
	$optstring .= 'ro';
    }

    my @extra_opts = ('-o', $optstring);

    if ($storage) {

	my $scfg = PVE::Storage::storage_config($storage_cfg, $storage);
	my $path = PVE::Storage::path($storage_cfg, $volid, $snapname);

	my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	    PVE::Storage::parse_volname($storage_cfg, $volid);

	$format = 'iso' if $vtype eq 'iso'; # allow to handle iso files

	if ($format eq 'subvol') {
	    if ($mount_path) {
		if ($snapname) {
		    if ($scfg->{type} eq 'zfspool') {
			my $path_arg = $path;
			$path_arg =~ s!^/+!!;
			PVE::Tools::run_command(['mount', '-o', 'ro', @extra_opts, '-t', 'zfs', $path_arg, $mount_path]);
		    } else {
			die "cannot mount subvol snapshots for storage type '$scfg->{type}'\n";
		    }
		} else {
		    if ($mountpoint->{ro}) {
			die "read-only bind mounts not supported\n";
		    }
		    PVE::Tools::run_command(['mount', '-o', 'bind', @extra_opts, $path, $mount_path]);
		}
	    }
	    return wantarray ? ($path, 0) : $path;
	} elsif ($format eq 'raw' || $format eq 'iso') {
	    my $use_loopdev = 0;
	    if ($scfg->{path}) {
		push @extra_opts, '-o', 'loop';
		$use_loopdev = 1;
	    } elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'lvm' ||
		     $scfg->{type} eq 'rbd' || $scfg->{type} eq 'lvmthin') {
		# do nothing
	    } else {
		die "unsupported storage type '$scfg->{type}'\n";
	    }
	    if ($mount_path) {
		if ($format eq 'iso') {
		    PVE::Tools::run_command(['mount', '-o', 'ro', @extra_opts, $path, $mount_path]);
		} elsif ($isBase || defined($snapname)) {
		    PVE::Tools::run_command(['mount', '-o', 'ro,noload', @extra_opts, $path, $mount_path]);
		} else {
		    PVE::Tools::run_command(['mount', @extra_opts, $path, $mount_path]);
		}
	    }
	    return wantarray ? ($path, $use_loopdev) : $path;
	} else {
	    die "unsupported image format '$format'\n";
	}
    } elsif ($type eq 'device') {
	PVE::Tools::run_command(['mount', @extra_opts, $volid, $mount_path]) if $mount_path;
	return wantarray ? ($volid, 0) : $volid;
    } elsif ($type eq 'bind') {
	if ($mountpoint->{ro}) {
	    die "read-only bind mounts not supported\n";
	    # Theoretically we'd have to execute both:
	    # mount -o bind $a $b
	    # mount -o bind,remount,ro $a $b
	}
	die "directory '$volid' does not exist\n" if ! -d $volid;
	&$check_mount_path($volid);
	PVE::Tools::run_command(['mount', '-o', 'bind', @extra_opts, $volid, $mount_path]) if $mount_path;
	return wantarray ? ($volid, 0) : $volid;
    }
    
    die "unsupported storage";
}

sub get_vm_volumes {
    my ($conf, $excludes) = @_;

    my $vollist = [];

    foreach_mountpoint($conf, sub {
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

sub mkfs {
    my ($dev, $rootuid, $rootgid) = @_;

    PVE::Tools::run_command(['mkfs.ext4', '-O', 'mmp',
			     '-E', "root_owner=$rootuid:$rootgid",
			     $dev]);
}

sub format_disk {
    my ($storage_cfg, $volid, $rootuid, $rootgid) = @_;

    if ($volid =~ m!^/dev/.+!) {
	mkfs($volid);
	return;
    }

    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "cannot format volume '$volid' with no storage\n" if !$storage;

    PVE::Storage::activate_volumes($storage_cfg, [$volid]);

    my $path = PVE::Storage::path($storage_cfg, $volid);

    my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	PVE::Storage::parse_volname($storage_cfg, $volid);

    die "cannot format volume '$volid' (format == $format)\n"
	if $format ne 'raw';

    mkfs($path, $rootuid, $rootgid);
}

sub destroy_disks {
    my ($storecfg, $vollist) = @_;

    foreach my $volid (@$vollist) {
	eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	warn $@ if $@;
    }
}

sub create_disks {
    my ($storecfg, $vmid, $settings, $conf) = @_;

    my $vollist = [];

    eval {
	my (undef, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
	my $chown_vollist = [];

	foreach_mountpoint($settings, sub {
	    my ($ms, $mountpoint) = @_;

	    my $volid = $mountpoint->{volume};
	    my $mp = $mountpoint->{mp};

	    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	    if ($storage && ($volid =~ m/^([^:\s]+):(\d+(\.\d+)?)$/)) {
		my ($storeid, $size_gb) = ($1, $2);

		my $size_kb = int(${size_gb}*1024) * 1024;

		my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		# fixme: use better naming ct-$vmid-disk-X.raw?

		if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
		    if ($size_kb > 0) {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw',
							   undef, $size_kb);
			format_disk($storecfg, $volid, $rootuid, $rootgid);
		    } else {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
							   undef, 0);
			push @$chown_vollist, $volid;
		    }
		} elsif ($scfg->{type} eq 'zfspool') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
					               undef, $size_kb);
		    push @$chown_vollist, $volid;
		} elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'lvm' || $scfg->{type} eq 'lvmthin') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
		    format_disk($storecfg, $volid, $rootuid, $rootgid);

		} elsif ($scfg->{type} eq 'rbd') {

		    die "krbd option must be enabled on storage type '$scfg->{type}'\n" if !$scfg->{krbd};
		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
		    format_disk($storecfg, $volid, $rootuid, $rootgid);
		} else {
		    die "unable to create containers on storage type '$scfg->{type}'\n";
		}
		push @$vollist, $volid;
		$mountpoint->{volume} = $volid;
		$mountpoint->{size} = $size_kb * 1024;
		$conf->{$ms} = print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
	    } else {
                # use specified/existing volid/dir/device
                $conf->{$ms} = print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
	    }
	});

	PVE::Storage::activate_volumes($storecfg, $chown_vollist, undef);
	foreach my $volid (@$chown_vollist) {
	    my $path = PVE::Storage::path($storecfg, $volid, undef);
	    chown($rootuid, $rootgid, $path);
	}
	PVE::Storage::deactivate_volumes($storecfg, $chown_vollist, undef);
    };
    # free allocated images on error
    if (my $err = $@) {
	destroy_disks($storecfg, $vollist);
        die $err;
    }
    return $vollist;
}

# bash completion helper

sub complete_os_templates {
    my ($cmdname, $pname, $cvalue) = @_;

    my $cfg = PVE::Storage::config();

    my $storeid;

    if ($cvalue =~ m/^([^:]+):/) {
	$storeid = $1;
    }

    my $vtype = $cmdname eq 'restore' ? 'backup' : 'vztmpl';
    my $data = PVE::Storage::template_list($cfg, $storeid, $vtype);

    my $res = [];
    foreach my $id (keys %$data) {
	foreach my $item (@{$data->{$id}}) {
	    push @$res, $item->{volid} if defined($item->{volid});
	}
    }

    return $res;
}

my $complete_ctid_full = sub {
    my ($running) = @_;

    my $idlist = vmstatus();

    my $active_hash = list_active_containers();

    my $res = [];

    foreach my $id (keys %$idlist) {
	my $d = $idlist->{$id};
	if (defined($running)) {
	    next if $d->{template};
	    next if $running && !$active_hash->{$id};
	    next if !$running && $active_hash->{$id};
	}
	push @$res, $id;

    }
    return $res;
};

sub complete_ctid {
    return &$complete_ctid_full();
}

sub complete_ctid_stopped {
    return &$complete_ctid_full(0);
}

sub complete_ctid_running {
    return &$complete_ctid_full(1);
}

sub parse_id_maps {
    my ($conf) = @_;

    my $id_map = [];
    my $rootuid = 0;
    my $rootgid = 0;

    my $lxc = $conf->{lxc};
    foreach my $entry (@$lxc) {
	my ($key, $value) = @$entry;
	next if $key ne 'lxc.id_map';
	if ($value =~ /^([ug])\s+(\d+)\s+(\d+)\s+(\d+)\s*$/) {
	    my ($type, $ct, $host, $length) = ($1, $2, $3, $4);
	    push @$id_map, [$type, $ct, $host, $length];
	    if ($ct == 0) {
		$rootuid = $host if $type eq 'u';
		$rootgid = $host if $type eq 'g';
	    }
	} else {
	    die "failed to parse id_map: $value\n";
	}
    }

    if (!@$id_map && $conf->{unprivileged}) {
	# Should we read them from /etc/subuid?
	$id_map = [ ['u', '0', '100000', '65536'],
	            ['g', '0', '100000', '65536'] ];
	$rootuid = $rootgid = 100000;
    }

    return ($id_map, $rootuid, $rootgid);
}

sub userns_command {
    my ($id_map) = @_;
    if (@$id_map) {
	return ['lxc-usernsexec', (map { ('-m', join(':', @$_)) } @$id_map), '--'];
    }
    return [];
}

1;
