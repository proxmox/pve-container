package PVE::LXC;

use strict;
use warnings;

use File::Path;
use Fcntl ':flock';

use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::SafeSyslog;
use PVE::INotify;

use Data::Dumper;

cfs_register_file('/lxc/', \&parse_lxc_config, \&write_lxc_config);

my $nodename = PVE::INotify::nodename();

my $valid_lxc_keys = {
    'lxc.arch' => 1,
    'lxc.include' => 1,
    'lxc.rootfs' => 1,
    'lxc.mount' => 1,
    'lxc.utsname' => 1,

    'lxc.cgroup.memory.limit_in_bytes' => 1,

    # pve related keys
    'pve.comment' => 1,
};

my $valid_network_keys = {
    type => 1,
    flags => 1,
    link => 1,
    mtu => 1,
    name => 1, # ifname inside container
    'veth.pair' => 1, # ifname at host (eth${vmid}.X)
    hwaddr => 1,
    ipv4 => 1,
    'ipv4.gateway' => 1,
    ipv6 => 1,
    'ipv6.gateway' => 1,
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
	next if $k !~ m/^net\d+$/;
	$done_hash->{$k} = 1;
	my $net = $data->{$k};
	$raw .= "lxc.network.type = $net->{type}\n";
	foreach my $subkey (sort keys %$net) {
	    next if $subkey eq 'type';
	    $raw .= "lxc.network.$subkey = $net->{$subkey}\n";
	}
    }

    foreach my $k (sort keys %$data) {
	next if $done_hash->{$k};
	die "found un-written value in config - implement this!";
    }

    print $raw;
    
    return $raw;
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
	    } elsif ($valid_network_keys->{$subkey}) {
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
	if ($line =~ m/^((?:pve|lxc)\.\S+)\s*=\s*(\S+)\s*$/) {
	    my ($name, $value) = ($1, $2);

	    die "inavlid key '$name'\n" if !$valid_lxc_keys->{$name};	    

	    die "multiple definitions for $name\n" if defined($data->{$name});

	    $data->{$name} = $value;
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
	description => "The number of CPUs for this container.",
	minimum => 1,
	default => 1,
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
    net0 => {
	optional => 1,
	type => 'string', format => 'pve-lxc-network',
	description => "Specifies network interfaces for the container.",
    },
};

# add JSON properties for create and set function
sub json_config_properties {
    my $prop = shift;

    foreach my $opt (keys %$confdesc) {
	$prop->{$opt} = $confdesc->{$opt};
    }

    return $prop;
}


sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc' }} : config_list();

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);

	my $d = $list->{$vmid};
	$d->{status} = 'stopped';

	my $cfspath = cfs_config_path($vmid);
	if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
	    print Dumper($conf);
	    $d->{name} = $conf->{'lxc.utsname'} || "CT$vmid";
	    $d->{name} =~ s/[\s]//g;

	}
    }

    return $list;
}

sub print_netif {
    my $net = shift;

    my $res = "pair=$net->{pair}";

    foreach my $k (qw(link hwaddr mtu name ipv4 ipv4.gateway ipv6 ipv6.gateway)) {
	next if !defined($net->{$k});
	$res .= ",$k=$net->{$k}";
    }
    
    return $res;
}


1;
