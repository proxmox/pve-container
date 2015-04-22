package PVE::LXC;

use strict;
use warnings;

use File::Path;
use Fcntl ':flock';

use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Tools qw($IPV6RE $IPV4RE);

use Data::Dumper;

cfs_register_file('/lxc/', \&parse_lxc_config, \&write_lxc_config);

PVE::JSONSchema::register_format('pve-lxc-network', \&verify_lxc_network);
sub verify_lxc_network {
    my ($value, $noerr) = @_;

    return $value if parse_lxc_network($value);

    return undef if $noerr;

    die "unable to parse network setting\n";
}

my $nodename = PVE::INotify::nodename();

sub parse_lxc_size {
    my ($name, $value) = @_;

    if ($value =~ m/^(\d+)(b|k|m|g)?$/i) {
	my ($res, $unit) = ($1, lc($2 || 'b'));

	return $res if $unit eq 'b';
	return $res*1024 if $unit eq 'k';
	return $res*1024*1024 if $unit eq 'm';
	return $res*1024*1024*1024 if $unit eq 'g';
    }

    return undef;
}

my $valid_lxc_keys = {
    'lxc.arch' => 'i386|x86|i686|x86_64|amd64',
    'lxc.include' => 1,
    'lxc.rootfs' => 1,
    'lxc.mount' => 1,
    'lxc.utsname' => 1,

    'lxc.id_map' => 1,
    
    'lxc.cgroup.memory.limit_in_bytes' => \&parse_lxc_size,
    'lxc.cgroup.memory.memsw.limit_in_bytes' => \&parse_lxc_size,
    'lxc.cgroup.cpu.cfs_period_us' => 1,
    'lxc.cgroup.cpu.cfs_quota_us' => 1,
    
    # mount related
    'lxc.mount' => 1,
    'lxc.mount.entry' => 1,
    'lxc.mount.auto' => 1,

    # not used by pve
    'lxc.tty' => 1,
    'lxc.pts' => 1,
    'lxc.haltsignal' => 1,
    'lxc.rebootsignal' => 1,	
    'lxc.stopsignal' => 1,
    'lxc.init_cmd' => 1,
    'lxc.console' => 1,
    'lxc.console.logfile' => 1,
    'lxc.devttydir' => 1,
    'lxc.autodev' => 1,
    'lxc.kmsg' => 1,
    'lxc.cap.drop' => 1,
    'lxc.cap.keep' => 1,
    'lxc.aa_profile' => 1,
    'lxc.aa_allow_incomplete' => 1,
    'lxc.se_context' => 1,
    'lxc.loglevel' => 1,
    'lxc.logfile' => 1,
    'lxc.environment' => 1,
    

    # autostart
    'lxc.start.auto' => 1,
    'lxc.start.delay' => 1,
    'lxc.start.order' => 1,
    'lxc.group' => 1,

    # hooks
    'lxc.hook.pre-start' => 1,
    'lxc.hook.pre-mount' => 1,
    'lxc.hook.mount' => 1,
    'lxc.hook.autodev' => 1,
    'lxc.hook.start' => 1,
    'lxc.hook.post-stop' => 1,
    'lxc.hook.clone' => 1,
    
    # pve related keys
    'pve.comment' => 1,
};

my $valid_lxc_network_keys = {
    type => 1,
    mtu => 1,
    name => 1, # ifname inside container
    'veth.pair' => 1, # ifname at host (eth${vmid}.X)
    hwaddr => 1,
};

my $valid_pve_network_keys = {
    bridge => 1,
    tag => 1,
    firewall => 1,
    ip => 1,
    gw => 1,
    ip6 => 1,
    gw6 => 1,
};

my $lxc_array_configs = {
    'lxc.network' => 1,
    'lxc.mount' => 1,
    'lxc.include' => 1,
};

sub write_lxc_config {
    my ($filename, $data) = @_;

    my $raw = "";

    return $raw if !$data;

    my $done_hash = { digest => 1};

    foreach my $k (sort keys %$data) {
	next if $k !~ m/^lxc\./;
	$done_hash->{$k} = 1;
	$raw .= "$k = $data->{$k}\n";
    }

    foreach my $k (sort keys %$data) {
	next if $k !~ m/^pve\./;
	$done_hash->{$k} = 1;
	$raw .= "$k = $data->{$k}\n";
    }

    foreach my $k (sort keys %$data) {
	next if $k !~ m/^net\d+$/;
	$done_hash->{$k} = 1;
	my $net = $data->{$k};
	$raw .= "lxc.network.type = $net->{type}\n";
	foreach my $subkey (sort keys %$net) {
	    next if $subkey eq 'type';
	    if ($valid_lxc_network_keys->{$subkey}) {
		$raw .= "lxc.network.$subkey = $net->{$subkey}\n";
	    } elsif ($valid_pve_network_keys->{$subkey}) {
		$raw .= "pve.network.$subkey = $net->{$subkey}\n";
	    } else {
		die "found invalid network key '$subkey'";
	    }
	}
    }

    foreach my $k (sort keys %$data) {
	next if $done_hash->{$k};
	die "found un-written value in config - implement this!";
    }

    return $raw;
}

sub parse_lxc_option {
    my ($name, $value) = @_;

    my $parser = $valid_lxc_keys->{$name};

    die "inavlid key '$name'\n" if !defined($parser);

    if ($parser eq '1') {
	return $value;		
    } elsif (ref($parser)) {
	my $res = &$parser($name, $value);
	return $res if defined($res);
    } else {
	# assume regex
	return $value if $value =~ m/^$parser$/;
    }
    
    die "unable to parse value '$value' for option '$name'\n";
}

sub parse_lxc_config {
    my ($filename, $raw) = @_;

    return undef if !defined($raw);

    my $data = {
	digest => Digest::SHA::sha1_hex($raw),
    };

    $filename =~ m|/lxc/(\d+)/config$|
	|| die "got strange filename '$filename'";

    my $vmid = $1;

    my $network_counter = 0;
    my $network_list = [];
    my $host_ifnames = {};

     my $find_next_hostif_name = sub {
	for (my $i = 0; $i < 10; $i++) {
	    my $name = "veth${vmid}.$i";
	    if (!$host_ifnames->{$name}) {
		$host_ifnames->{$name} = 1;
		return $name;
	    }
	}

	die "unable to find free host_ifname"; # should not happen
    };

    my $push_network = sub {
	my ($netconf) = @_;
	return if !$netconf;
	push @{$network_list}, $netconf;
	$network_counter++;
	if (my $netname = $netconf->{'veth.pair'}) {
	    if ($netname =~ m/^veth(\d+).(\d)$/) {
		die "wrong vmid for network interface pair\n" if $1 != $vmid;
		my $host_ifnames->{$netname} = 1;
	    } else {
		die "wrong network interface pair\n";
	    }
	}
    };

    my $network;

    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
	my $line = $1;

	next if $line =~ m/^\#/;
	next if $line =~ m/^\s*$/;

	if ($line =~ m/^lxc\.network\.(\S+)\s*=\s*(\S+)\s*$/) {
	    my ($subkey, $value) = ($1, $2);
	    if ($subkey eq 'type') {
		&$push_network($network);
		$network = { type => $value };
	    } elsif ($valid_lxc_network_keys->{$subkey}) {
		$network->{$subkey} = $value;
	    } else {
		die "unable to parse config line: $line\n";
	    }
	    next;
	}
	if ($line =~ m/^pve\.network\.(\S+)\s*=\s*(\S+)\s*$/) {
	    my ($subkey, $value) = ($1, $2);
	    if ($valid_pve_network_keys->{$subkey}) {
		$network->{$subkey} = $value;
	    } else {
		die "unable to parse config line: $line\n";
	    }
	    next;
	}
	if ($line =~ m/^(pve.comment)\s*=\s*(\S.*)\s*$/) {
	    my ($name, $value) = ($1, $2);
	    $data->{$name} = $value;
	    next;
	}
	if ($line =~ m/^((?:pve|lxc)\.\S+)\s*=\s*(\S.*)\s*$/) {
	    my ($name, $value) = ($1, $2);

	    die "multiple definitions for $name\n" if defined($data->{$name});

	    $data->{$name} = parse_lxc_option($name, $value);		    
	    next;
	}

	die "unable to parse config line: $line\n";
    }

    &$push_network($network);

    foreach my $net (@{$network_list}) {
	$net->{'veth.pair'} = &$find_next_hostif_name() if !$net->{'veth.pair'};
	$net->{hwaddr} =  PVE::Tools::random_ether_addr() if !$net->{hwaddr};
	die "unsupported network type '$net->{type}'\n" if $net->{type} ne 'veth';

	if ($net->{'veth.pair'} =~ m/^veth\d+.(\d+)$/) {
	    $data->{"net$1"} = $net;
	}
    }

    return $data;
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
    return "nodes/$node/lxc/$vmid/config";
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

sub write_config {
    my ($vmid, $conf) = @_;

    my $cfspath = cfs_config_path($vmid);

    PVE::Cluster::cfs_write_file($cfspath, $conf);
}

my $tempcounter = 0;
sub write_temp_config {
    my ($vmid, $conf) = @_;

    $tempcounter++;
    my $filename = "/tmp/temp-lxc-conf-$vmid-$$-$tempcounter.conf";

    my $raw =  write_lxc_config($filename, $conf);

    PVE::Tools::file_set_contents($filename, $raw);

    return $filename;
}

sub lock_container {
    my ($vmid, $timeout, $code, @param) = @_;

    my $lockdir = "/run/lock/lxc";
    my $lockfile = "$lockdir/pve-config-{$vmid}.lock";

    File::Path::make_path($lockdir);

    my $res = PVE::Tools::lock_file($lockfile, $timeout, $code, @param);

    die $@ if $@;

    return $res;
}

my $confdesc = {
    onboot => {
	optional => 1,
	type => 'boolean',
	description => "Specifies whether a VM will be started during system bootup.",
	default => 0,
    },
    cpus => {
	optional => 1,
	type => 'integer',
	description => "The number of CPUs for this container (0 is unlimited).",
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
	default => 1000,
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
    disk => {
	optional => 1,
	type => 'number',
	description => "Amount of disk space for the VM in GB. A zero indicates no limits.",
	minimum => 0,
	default => 2,
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
};

my $MAX_LXC_NETWORKS = 10;
for (my $i = 0; $i < $MAX_LXC_NETWORKS; $i++) {
    $confdesc->{"net$i"} = {
	optional => 1,
	type => 'string', format => 'pve-lxc-network',
	description => "Specifies network interfaces for the container.",
    };
}

sub option_exists {
    my ($name) = @_;

    return defined($confdesc->{$name});
}

# add JSON properties for create and set function
sub json_config_properties {
    my $prop = shift;

    foreach my $opt (keys %$confdesc) {
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
	    if ($path =~ m!^@/etc/pve/lxc/(\d+)/command$!) {
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

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc' }} : config_list();

    my $active_hash = list_active_containers();
    
    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};
	$d->{status} = $active_hash->{$vmid} ? 'running' : 'stopped';

	my $cfspath = cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};
	
	$d->{name} = $conf->{'lxc.utsname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;
	    
	$d->{cpus} = 0;

	my $cfs_period_us = $conf->{'lxc.cgroup.cpu.cfs_period_us'};
	my $cfs_quota_us = $conf->{'lxc.cgroup.cpu.cfs_quota_us'};

	if ($cfs_period_us && $cfs_quota_us) {
	    $d->{cpus} = int($cfs_quota_us/$cfs_period_us);
	}
	
	$d->{disk} = 0;
	$d->{maxdisk} = 1;
	if (my $private = $conf->{'lxc.rootfs'}) {
	    my $res = PVE::Tools::df($private, 2);
	    $d->{disk} = $res->{used};
	    $d->{maxdisk} = $res->{total};
	}
	
	$d->{mem} = 0;
	$d->{swap} = 0;
	$d->{maxmem} = ($conf->{'lxc.cgroup.memory.limit_in_bytes'}||0) +
	    ($conf->{'lxc.cgroup.memory.memsw.limit_in_bytes'}||0);

	$d->{uptime} = 0;
	$d->{cpu} = 0;

	$d->{netout} = 0;
	$d->{netin} = 0;

	$d->{diskread} = 0;
	$d->{diskwrite} = 0;
    }
    
    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};
	next if $d->{status} ne 'running';

	$d->{uptime} = 100; # fixme:

	$d->{mem} = read_cgroup_value('memory', $vmid, 'memory.usage_in_bytes');
	$d->{swap} = read_cgroup_value('memory', $vmid, 'memory.memsw.usage_in_bytes') - $d->{mem};
    }
    
    return $list;
}


sub print_lxc_network {
    my $net = shift;

    die "no network bridge defined\n" if !$net->{bridge};

    my $res = "bridge=$net->{bridge}";

    foreach my $k (qw(hwaddr mtu name ip gw ip6 gw6 firewall tag)) {
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
    $res->{hwaddr} = PVE::Tools::random_ether_addr() if !$res->{mac};
   
    return $res;
}

sub read_cgroup_value {
    my ($group, $vmid, $name, $full) = @_;

    my $path = "/sys/fs/cgroup/$group/lxc/$vmid/$name";

    return PVE::Tools::file_get_contents($path) if $full;

    return PVE::Tools::file_read_firstline($path);
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

sub update_lxc_config {
    my ($vmid, $conf, $running, $param, $delete) = @_;

    # fixme: hotplug
    die "unable to modify config while container is running\n" if $running;

    if (defined($delete)) {
	foreach my $opt (@$delete) {
	    if ($opt eq 'hostname' || $opt eq 'memory') {
		die "unable to delete required option '$opt'\n";
	    } elsif ($opt eq 'swap') {
		delete $conf->{'lxc.cgroup.memory.memsw.limit_in_bytes'};
	    } elsif ($opt eq 'description') {
		delete $conf->{'pve.comment'};
	    } elsif ($opt =~ m/^net\d$/) {
		delete $conf->{$opt};
	    } else {
		die "implement me"
	    }
	}
    }

    foreach my $opt (keys %$param) {
	my $value = $param->{$opt};
	if ($opt eq 'hostname') {
	    $conf->{'lxc.utsname'} = $value;
	} elsif ($opt eq 'memory') {
	    $conf->{'lxc.cgroup.memory.limit_in_bytes'} = $value*1024*1024;
	} elsif ($opt eq 'swap') {
	    my $mem =  $conf->{'lxc.cgroup.memory.limit_in_bytes'};
	    $mem = $param->{memory}*1024*1024 if $param->{memory};
	    $conf->{'lxc.cgroup.memory.memsw.limit_in_bytes'} = $mem + $value*1024*1024;
	} elsif ($opt eq 'cpus') {
	    if ($value > 0) {
		my $cfs_period_us = 100000;
		$conf->{'lxc.cgroup.cpu.cfs_period_us'} = $cfs_period_us;
		$conf->{'lxc.cgroup.cpu.cfs_quota_us'} = $cfs_period_us*$value;
	    } else {
		delete $conf->{'lxc.cgroup.cpu.cfs_period_us'};
		delete $conf->{'lxc.cgroup.cpu.cfs_quota_us'};
	    }
	} elsif ($opt eq 'description') {
	    $conf->{'pve.comment'} = PVE::Tools::encode_text($value);
	} elsif ($opt =~ m/^net(\d+)$/) {
	    my $netid = $1;
	    my $net = PVE::LXC::parse_lxc_network($value);
	    $net->{'veth.pair'} = "veth${vmid}.$netid";
	    $conf->{$opt} = $net;
	} else {
	    die "implement me"
	}
    }
}
    
1;
