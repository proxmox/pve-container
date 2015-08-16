package PVE::LXC;

use strict;
use warnings;
use POSIX qw(EINTR);

use File::Path;
use Fcntl ':flock';

use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::Storage;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw($IPV6RE $IPV4RE);
use PVE::Network;

use Data::Dumper;

my $nodename = PVE::INotify::nodename();

cfs_register_file('/lxc/', \&parse_pct_config, \&write_pct_config);

PVE::JSONSchema::register_format('pve-lxc-network', \&verify_lxc_network);
sub verify_lxc_network {
    my ($value, $noerr) = @_;

    return $value if parse_lxc_network($value);

    return undef if $noerr;

    die "unable to parse network setting\n";
}

PVE::JSONSchema::register_format('pve-ct-mountpoint', \&verify_ct_mountpoint);
sub verify_ct_mountpoint {
    my ($value, $noerr) = @_;

    return $value if parse_ct_mountpoint($value);

    return undef if $noerr;

    die "unable to parse CT mountpoint options\n";
}

PVE::JSONSchema::register_standard_option('pve-ct-rootfs', {
    type => 'string', format => 'pve-ct-mountpoint',
    typetext => '[volume=]volume,] [,backup=yes|no] [,size=\d+]',
    description => "Use volume as container root.",
    optional => 1,
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
	enum => ['debian', 'ubuntu', 'centos'],
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
	description => "Limit of CPU usage. Note if the computer has 2 CPUs, it has total of '2' CPU time. Value '0' indicates no CPU limit.",
	minimum => 0,
	maximum => 128,
	default => 0,
    },
    cpuunits => {
	optional => 1,
	type => 'integer',
	description => "CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to weights of all the other running VMs.\n\nNOTE: You can disable fair-scheduler configuration by setting this to 0.",
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
	type => 'string',
	maxLength => 255,
    },
    description => {
	optional => 1,
	type => 'string',
	description => "Container description. Only used on the configuration web interface.",
    },
    searchdomain => {
	optional => 1,
	type => 'string',
	description => "Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain or nameserver.",
    },
    nameserver => {
	optional => 1,
	type => 'string',
	description => "Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain or nameserver.",
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
    'lxc.rootfs' => 1,
    'lxc.rootfs.mount' => 1,
    'lxc.rootfs.options' => 1,
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
    'lxc.' => 1,
    'lxc.' => 1,
    'lxc.' => 1,
    'lxc.' => 1,
};

my $MAX_LXC_NETWORKS = 10;
for (my $i = 0; $i < $MAX_LXC_NETWORKS; $i++) {
    $confdesc->{"net$i"} = {
	optional => 1,
	type => 'string', format => 'pve-lxc-network',
	description => "Specifies network interfaces for the container.\n\n".
	    "The string should have the follow format:\n\n".
	    "-net<[0-9]> bridge=<vmbr<Nummber>>[,hwaddr=<MAC>]\n".
	    "[,mtu=<Number>][,name=<String>][,ip=<IPv4Format/CIDR>]\n".
	    ",ip6=<IPv6Format/CIDR>][,gw=<GatwayIPv4>]\n".
	    ",gw6=<GatwayIPv6>][,firewall=<[1|0]>][,tag=<VlanNo>]",
    };
}

my $MAX_MOUNT_POINTS = 10;
for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
    $confdesc->{"mp$i"} = {
	optional => 1,
	type => 'string', format => 'pve-ct-mountpoint',
	typetext => '[volume=]volume,] [,backup=yes|no] [,size=\d+] [,mp=mountpoint]',
	description => "Use volume as container mount point.",
	optional => 1,
    };
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
	    $raw .= "$key: $conf->{$key}\n";
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

	if ($line =~ m/^(lxc\.[a-z0-9\.]+)(:|\s*=)\s*(.*?)\s*$/) {
	    my $key = $1;
	    my $value = $3;
	    if ($valid_lxc_conf_keys->{$key} || $key =~ m/^lxc\.cgroup\./) {
		push @{$conf->{lxc}}, [$key, $value];
	    } else {
		warn "vm $vmid - unable to parse config: $line\n";
	    }
	} elsif ($line =~ m/^(description):\s*(.*\S)\s*$/) {
	    $descr .= PVE::Tools::decode_text($2);
	} elsif ($line =~ m/snapstate:\s*(prepare|delete)\s*$/) {
	    $conf->{snapstate} = $1;
	} elsif ($line =~ m/^([a-z][a-z_]*\d*):\s*(\S+)\s*$/) {
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
    my ($vmid) = @_;

    my $cfspath = cfs_config_path($vmid);

    my $conf = PVE::Cluster::cfs_read_file($cfspath);
    die "container $vmid does not exists\n" if !defined($conf);

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
# can be called multiple times and succeeds for the same process.

my $lock_handles =  {};
my $lockdir = "/run/lock/lxc";

sub lock_filename {
    my ($vmid) = @_;

    return "$lockdir/pve-config-{$vmid}.lock";
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

	    $lock_handles->{$$}->{$filename}->{refcount}++;

	    print STDERR " OK\n";
	}
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
    my ($vmid) = @_;

    my $cmd = ['lxc-attach', '-n', $vmid, '--', 'df',  '-P', '-B', '1', '/'];

    my $res = {
	total => 0,
	used => 0,
	avail => 0,
    };

    my $parser = sub {
	my $line = shift;
	if (my ($fsid, $total, $used, $avail) = $line =~
	    m/^(\S+.*)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+%\s.*$/) {
	    $res = {
		total => $total,
		used => $used,
		avail => $avail,
	    };
	}
    };
    eval { PVE::Tools::run_command($cmd, timeout => 1, outfunc => $parser); };
    warn $@ if $@;

    return $res;
}

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc' }} : config_list();

    my $active_hash = list_active_containers();

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};

	my $running = defined($active_hash->{$vmid});

	$d->{status} = $running ? 'running' : 'stopped';

	my $cfspath = cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	$d->{name} = $conf->{'hostname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;

	$d->{cpus} = $conf->{cpulimit} // 0;

	if ($running) {
	    my $res = get_container_disk_usage($vmid);
	    $d->{disk} = $res->{used};
	    $d->{maxdisk} = $res->{total};
	} else {
	    $d->{disk} = 0;
	    # use 4GB by default ??
	    if (my $rootfs = $conf->{rootfs}) {
		my $rootinfo = parse_ct_mountpoint($rootfs);
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
	next if $d->{status} ne 'running';

	$d->{uptime} = 100; # fixme:

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
    }

    return $list;
}

my $parse_size = sub {
    my ($value) = @_;

    return undef if $value !~ m/^(\d+(\.\d+)?)([KMG])?$/;
    my ($size, $unit) = ($1, $3);
    if ($unit) {
	if ($unit eq 'K') {
	    $size = $size * 1024;
	} elsif ($unit eq 'M') {
	    $size = $size * 1024 * 1024;
	} elsif ($unit eq 'G') {
	    $size = $size * 1024 * 1024 * 1024;
	}
    }
    return int($size);
};

sub parse_ct_mountpoint {
    my ($data) = @_;

    $data //= '';

    my $res = {};

    foreach my $p (split (/,/, $data)) {
	next if $p =~ m/^\s*$/;

	if ($p =~ m/^(volume|backup|size|mp)=(.+)$/) {
	    my ($k, $v) = ($1, $2);
	    return undef if defined($res->{$k});
	    $res->{$k} = $v;
	} else {
	    if (!$res->{volume} && $p !~ m/=/) {
		$res->{volume} = $p;
	    } else {
		return undef;
	    }
	}
    }

    return undef if !$res->{volume};

    return undef if $res->{backup} && $res->{backup} !~ m/^(yes|no)$/;

    if ($res->{size}) {
	return undef if !defined($res->{size} = &$parse_size($res->{size}));
    }

    return $res;
}

sub print_ct_mountpoint {
    my ($info) = @_;

    my $opts = '';

    die "missing volume\n" if !$info->{volume};

    foreach my $o ('size', 'backup') {
	$opts .= ",$o=$info->{$o}" if defined($info->{$o});
    }

    return "$info->{volume}$opts";
}

sub print_lxc_network {
    my $net = shift;

    die "no network name defined\n" if !$net->{name};

    my $res = "name=$net->{name}";

    foreach my $k (qw(hwaddr mtu bridge ip gw ip6 gw6 firewall tag)) {
	next if !defined($net->{$k});
	$res .= ",$k=$net->{$k}";
    }

    return $res;
}

sub parse_lxc_network {
    my ($data) = @_;

    my $res = {};

    return $res if !$data;

    foreach my $pv (split (/,/, $data)) {
	if ($pv =~ m/^(bridge|hwaddr|mtu|name|ip|ip6|gw|gw6|firewall|tag)=(\S+)$/) {
	    $res->{$1} = $2;
	} else {
	    return undef;
	}
    }

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

	# serach for lxc-console -n <vmid>
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
    PVE::Tools::run_command(['lxc-info', '-n', $vmid], outfunc => $parser);

    die "unable to get PID for CT $vmid (not running?)\n" if !$pid;

    return $pid;
}

my $ipv4_reverse_mask = [
    '0.0.0.0',
    '128.0.0.0',
    '192.0.0.0',
    '224.0.0.0',
    '240.0.0.0',
    '248.0.0.0',
    '252.0.0.0',
    '254.0.0.0',
    '255.0.0.0',
    '255.128.0.0',
    '255.192.0.0',
    '255.224.0.0',
    '255.240.0.0',
    '255.248.0.0',
    '255.252.0.0',
    '255.254.0.0',
    '255.255.0.0',
    '255.255.128.0',
    '255.255.192.0',
    '255.255.224.0',
    '255.255.240.0',
    '255.255.248.0',
    '255.255.252.0',
    '255.255.254.0',
    '255.255.255.0',
    '255.255.255.128',
    '255.255.255.192',
    '255.255.255.224',
    '255.255.255.240',
    '255.255.255.248',
    '255.255.255.252',
    '255.255.255.254',
    '255.255.255.255',
];

# Note: we cannot use Net:IP, because that only allows strict
# CIDR networks
sub parse_ipv4_cidr {
    my ($cidr, $noerr) = @_;

    if ($cidr =~ m!^($IPV4RE)(?:/(\d+))$! && ($2 > 7) &&  ($2 < 32)) {
	return { address => $1, netmask => $ipv4_reverse_mask->[$2] };
    }

    return undef if $noerr;

    die "unable to parse ipv4 address/mask\n";
}

sub check_lock {
    my ($conf) = @_;

    die "VM is locked ($conf->{'lock'})\n" if $conf->{'lock'};
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

    my $ostype = $conf->{ostype} || die "missing 'ostype' - internal error";
    if ($ostype eq 'debian' || $ostype eq 'ubuntu' || $ostype eq 'centos') {
	$raw .= "lxc.include = /usr/share/lxc/config/$ostype.common.conf\n";
    } else {
	die "implement me";
    }

    if (!has_dev_console($conf)) {
	$raw .= "lxc.console = none\n";
	$raw .= "lxc.cgroup.devices.deny = c 5:1 rwm\n";
    }

    my $ttycount = get_tty_count($conf);
    $raw .= "lxc.tty = $ttycount\n";

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

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    my $volid = $rootinfo->{volume};
    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid);

    my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	PVE::Storage::parse_volname($storage_cfg, $volid);

    die "unable to use template as rootfs\n" if $isBase;
    
    my $scfg = PVE::Storage::storage_config($storage_cfg, $storage);
    my $path = PVE::Storage::path($storage_cfg, $volid);
    
    if ($format eq 'subvol') {
	$raw .= "lxc.rootfs = $path\n";
    } elsif ($format eq 'raw') {
	if ($scfg->{path}) {
	    $raw .= "lxc.rootfs = loop:$path\n";
	} elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'rbd') {
	    $raw .= "lxc.rootfs = $path\n";
	} else {
	    die "unsupported storage type '$scfg->{type}'\n";
	}
    } else {
	die "unsupported image format '$format'\n";
    }

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

sub update_pct_config {
    my ($vmid, $conf, $running, $param, $delete) = @_;

    my @nohotplug;

    my $rootdir;
    if ($running) {
	my $pid = find_lxc_pid($vmid);
	$rootdir = "/proc/$pid/root";
    }

    if (defined($delete)) {
	foreach my $opt (@$delete) {
	    if ($opt eq 'hostname' || $opt eq 'memory' || $opt eq 'rootfs') {
		die "unable to delete required option '$opt'\n";
	    } elsif ($opt eq 'swap') {
		delete $conf->{$opt};
		write_cgroup_value("memory", $vmid, "memory.memsw.limit_in_bytes", -1);
	    } elsif ($opt eq 'description' || $opt eq 'onboot' || $opt eq 'startup' ||
		     $opt eq 'cmode') {
		delete $conf->{$opt};
	    } elsif ($opt eq 'nameserver' || $opt eq 'searchdomain' ||
		     $opt eq 'tty' || $opt eq 'console') {
		delete $conf->{$opt};
		push @nohotplug, $opt;
		next if $running;
	    } elsif ($opt =~ m/^net(\d)$/) {
		delete $conf->{$opt};
		next if !$running;
		my $netid = $1;
		PVE::Network::veth_delete("veth${vmid}i$netid");
	    } else {
		die "implement me"
	    }
	    PVE::LXC::write_config($vmid, $conf) if $running;
	}
    }

    # There's no separate swap size to configure, there's memory and "total"
    # memory (iow. memory+swap). This means we have to change them together.
    my $wanted_memory = PVE::Tools::extract_param($param, 'memory');
    my $wanted_swap =  PVE::Tools::extract_param($param, 'swap');
    if (defined($wanted_memory) || defined($wanted_swap)) {

	$wanted_memory //= ($conf->{memory} || 512);
	$wanted_swap //=  ($conf->{swap} || 0);

        my $total = $wanted_memory + $wanted_swap;
	if ($running) {
	    write_cgroup_value("memory", $vmid, "memory.limit_in_bytes", int($wanted_memory*1024*1024));
	    write_cgroup_value("memory", $vmid, "memory.memsw.limit_in_bytes", int($total*1024*1024));
	}
	$conf->{memory} = $wanted_memory;
	$conf->{swap} = $wanted_swap;

	PVE::LXC::write_config($vmid, $conf) if $running;
    }

    foreach my $opt (keys %$param) {
	my $value = $param->{$opt};
	if ($opt eq 'hostname') {
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'onboot') {
	    $conf->{$opt} = $value ? 1 : 0;
	} elsif ($opt eq 'startup') {
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'cmode') {
	    $conf->{$opt} = $value;
	} elsif ($opt eq 'tty' || $opt eq 'console') {
	    $conf->{$opt} = $value;
	    push @nohotplug, $opt;
	    next if $running;
	} elsif ($opt eq 'nameserver') {
	    my $list = verify_nameserver_list($value);
	    $conf->{$opt} = $list;
	    push @nohotplug, $opt;
	    next if $running;
	} elsif ($opt eq 'searchdomain') {
	    my $list = verify_searchdomain_list($value);
	    $conf->{$opt} = $list;
	    push @nohotplug, $opt;
	    next if $running;
	} elsif ($opt eq 'cpulimit') {
	    $conf->{$opt} = $value;
	    push @nohotplug, $opt; # fixme: hotplug
	    next;
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
	} else {
	    die "implement me: $opt";
	}
	PVE::LXC::write_config($vmid, $conf) if $running;
    }

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
	if ($ipv6 =~ /^(dhcp|manual)$/) {
	    $ipv6 = undef;
	} else {
	    $ipv6 =~ s!/\d+$!!;
	}
    }

    return ($ipv4, $ipv6);
}


sub destroy_lxc_container {
    my ($storage_cfg, $vmid, $conf) = @_;

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    if (defined($rootinfo->{volume})) {
	my ($vtype, $name, $owner) = PVE::Storage::parse_volname($storage_cfg, $rootinfo->{volume});
	PVE::Storage::vdisk_free($storage_cfg, $rootinfo->{volume}) if $vmid == $owner;;
    }
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
            PVE::LXC::foreach_mountpoint($conf, sub {
		my ($ms, $mountpoint) = @_;
		PVE::Storage::deactivate_volumes($storage_cfg, [$mountpoint->{volume}]);
            });
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
	    PVE::LXC::write_config($vmid, $conf);

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
		    PVE::LXC::write_config($vmid, $conf);
		}

		PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall});
		foreach (qw(bridge tag firewall)) {
		    $oldnet->{$_} = $newnet->{$_} if $newnet->{$_};
		}
		$conf->{$opt} = print_lxc_network($oldnet);
		PVE::LXC::write_config($vmid, $conf);
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
    PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall});

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

    PVE::LXC::write_config($vmid, $conf);
}

sub update_ipconfig {
    my ($vmid, $conf, $opt, $eth, $newnet, $rootdir) = @_;

    my $lxc_setup = PVE::LXCSetup->new($conf, $rootdir);

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
	if ($change_ip && $newip && $newip !~ /^(?:auto|dhcp)$/) {
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
		eval { &$ipcmd($family_opt, 'route', 'replace', 'default', 'via', $newgw); };
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
	PVE::LXC::write_config($vmid, $conf);
	$lxc_setup->setup_network($conf);
    };

    &$change_ip_config(4);
    &$change_ip_config(6);

}

# Internal snapshots

# NOTE: Snapshot create/delete involves several non-atomic
# action, and can take a long time.
# So we try to avoid locking the file and use 'lock' variable
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
	die "snapshot feature is not available\n" if !has_feature('snapshot', $conf, $storecfg);

	$snap = $conf->{snapshots}->{$snapname} = {};

	&$snapshot_copy_config($conf, $snap);

	$snap->{'snapstate'} = "prepare";
	$snap->{'snaptime'} = time();
	$snap->{'description'} = $comment if $comment;
	$conf->{snapshots}->{$snapname} = $snap;

	PVE::LXC::write_config($vmid, $conf);
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

	PVE::LXC::write_config($vmid, $conf);
    };

    lock_container($vmid, 10 ,$updatefn);
};

sub has_feature {
    my ($feature, $conf, $storecfg, $snapname) = @_;
    
    #Fixme add other drives if necessary.
    my $err;

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    $err = 1 if !PVE::Storage::volume_has_feature($storecfg, $feature, $rootinfo->{volume}, $snapname);

    return $err ? 0 : 1;
}

sub snapshot_create {
    my ($vmid, $snapname, $comment) = @_;

    my $snap = &$snapshot_prepare($vmid, $snapname, $comment);

    my $conf = load_config($vmid);

    my $cmd = "/usr/bin/lxc-freeze -n $vmid";
    my $running = check_running($vmid);
    eval {
	if ($running) {
	    PVE::Tools::run_command($cmd);
	};

	my $storecfg = PVE::Storage::config();
	my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
	my $volid = $rootinfo->{volume};

	$cmd = "/usr/bin/lxc-unfreeze -n $vmid";
	if ($running) {
	    PVE::Tools::run_command($cmd);
	};

	PVE::Storage::volume_snapshot($storecfg, $volid, $snapname);
	&$snapshot_commit($vmid, $snapname);
    };
    if(my $err = $@) {
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

	PVE::LXC::write_config($vmid, $conf);
    };

    lock_container($vmid, 10, $updatefn);

    my $storecfg = PVE::Storage::config();

    my $del_snap =  sub {

	check_lock($conf);

	if ($conf->{parent} eq $snapname) {
	    if ($conf->{snapshots}->{$snapname}->{snapname}) {
		$conf->{parent} = $conf->{snapshots}->{$snapname}->{parent};
	    } else {
		delete $conf->{parent};
	    }
	}

	delete $conf->{snapshots}->{$snapname};

	PVE::LXC::write_config($vmid, $conf);
    };

    my $rootfs = $conf->{snapshots}->{$snapname}->{rootfs};
    my $rootinfo = PVE::LXC::parse_ct_mountpoint($rootfs);
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
    my $rootinfo = PVE::LXC::parse_ct_mountpoint($rootfs);
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

	PVE::LXC::write_config($vmid, $conf);
    };

    my $unlockfn = sub {
	delete $conf->{lock};
	PVE::LXC::write_config($vmid, $conf);
    };

    lock_container($vmid, 10, $updatefn);

    PVE::Storage::volume_snapshot_rollback($storecfg, $volid, $snapname);

    lock_container($vmid, 5, $unlockfn);
}

sub template_create {
    my ($vmid, $conf) = @_;

    my $storecfg = PVE::Storage::config();

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
    my $volid = $rootinfo->{volume};

    die "Template feature is not available for '$volid'\n"
	if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);

    PVE::Storage::activate_volumes($storecfg, [$volid]);

    my $template_volid = PVE::Storage::vdisk_create_base($storecfg, $volid);
    $rootinfo->{volume} = $template_volid;
    $conf->{rootfs} = print_ct_mountpoint($rootinfo);

    write_config($vmid, $conf);
}

sub is_template {
    my ($conf) = @_;

    return 1 if defined $conf->{template} && $conf->{template} == 1;
}

sub foreach_mountpoint {
    my ($conf, $func) = @_;

    my $mountpoint = parse_ct_mountpoint($conf->{rootfs});
    $mountpoint->{mp} = '/'; # just to be sure
    &$func('rootfs', $mountpoint);

    for (my $i = 0; $i < $MAX_MOUNT_POINTS; $i++) {
	my $key = "mp$i";
	next if !defined($conf->{$key});
	$mountpoint = parse_ct_mountpoint($conf->{$key});
	&$func($key, $mountpoint);
    }
}

sub loopdevices_list {

    my $loopdev = {};
    my $parser = sub {
	my $line = shift;
	if ($line =~ m/^(\/dev\/loop\d+)\s+\d\s+\d\s+\d\s+\d\s(\S+)$/) {
	    $loopdev->{$1} = $2;
	}
    };

    PVE::Tools::run_command(['losetup'], outfunc => $parser);

    return $loopdev;
}

sub blockdevices_list {

    my $bdevs = {};
    dir_glob_foreach("/sys/dev/block/", '(\d+):(\d+)', sub {
        my (undef, $major, $minor) = @_;
        my $bdev = readlink("/sys/dev/block/$major:$minor");
        $bdev =~ s/\.\.\/\.\.\/devices\/virtual\/block\//\/dev\//;
        $bdevs->{$bdev}->{major} = $major;
        $bdevs->{$bdev}->{minor} = $minor;
    });
    return $bdevs;
}

sub find_loopdev {
    my ($loopdevs, $path) = @_;

    foreach my $dev (keys %$loopdevs){
	return $dev if $loopdevs->{$dev} eq $path;
    }
}
1;
