package PVE::LXCSetup::Base;

use strict;
use warnings;

use PVE::Tools;

my $update_etc_hosts = sub {
    my ($etc_hosts_data, $hostip, $oldname, $newname, $searchdomains) = @_;

    my $done = 0;

    my @lines;

    my $extra_names = '';
    foreach my $domain (PVE::Tools::split_list($searchdomains)) {
	$extra_names .= ' ' if $extra_names;
	$extra_names .= "$newname.$domain";
    }
    
    foreach my $line (split(/\n/, $etc_hosts_data)) {
	if ($line =~ m/^#/ || $line =~ m/^\s*$/) {
	    push @lines, $line;
	    next;
	}

	my ($ip, @names) = split(/\s+/, $line);
	if (($ip eq '127.0.0.1') || ($ip eq '::1')) {
	    push @lines, $line;
	    next;
	}
	
	my $found = 0;
	foreach my $name (@names) {
	    if ($name eq $oldname || $name eq $newname) {
		$found = 1;
	    } else {
		# fixme: record extra names?
	    }
	}
	$found = 1 if defined($hostip) && ($ip eq $hostip);
	
	if ($found) {
	    if (!$done) {
		if (defined($hostip)) {
		    push @lines, "$ip $extra_names $newname";
		} else {
		    push @lines, "127.0.1.1 $newname";
		}
		$done = 1;
	    }
	    next;
	} else {
	    push @lines, $line;
	}
    }

    if (!$done) {
	if (defined($hostip)) {
	    push @lines, "$hostip $extra_names $newname";
	} else {
	    push @lines, "127.0.1.1 $newname";
	}	
    }

    my $found_localhost = 0;
    foreach my $line (@lines) {
	if ($line =~ m/^127.0.0.1\s/) {
	    $found_localhost = 1;
	    last;
	}
    }

    if (!$found_localhost) {
	unshift @lines, "127.0.0.1 localhost.localnet localhost";
    }
    
    $etc_hosts_data = join("\n", @lines) . "\n";
    
    return $etc_hosts_data;
};

sub set_hostname {
    my ($class, $conf) = @_;
    
    my $hostname = $conf->{'lxc.utsname'} || 'localhost';

    $hostname =~ s/\..*$//;

    my $rootfs = $conf->{'lxc.rootfs'};

    my $hostname_fn = "$rootfs/etc/hostname";
    
    my $oldname = PVE::Tools::file_read_firstline($hostname_fn) || 'localhost';

    my $hosts_fn = "$rootfs/etc/hosts";
    my $etc_hosts_data = '';
    
    if (-f $hosts_fn) {
	$etc_hosts_data =  PVE::Tools::file_get_contents($hosts_fn);
    }

    my $hostip = undef; # fixme;
    
    $etc_hosts_data = &$update_etc_hosts($etc_hosts_data, $hostip, $oldname, 
					 $hostname, $conf->{'pve.searchdomain'});
  
    PVE::Tools::file_set_contents($hostname_fn, "$hostname\n");
    PVE::Tools::file_set_contents($hosts_fn, $etc_hosts_data);
}

sub setup_network {
    my ($class, $conf) = @_;

    die "please implement this inside subclass"
}

sub setup_init {
    my ($class, $conf) = @_;

    die "please implement this inside subclass"
}

sub pre_start_hook {
    my ($class, $conf) = @_;

    $class->setup_init($conf);
    $class->setup_network($conf);
    $class->set_hostname($conf);

    # fixme: what else ?
}

sub post_create_hook {
    my ($class, $conf) = @_;

    $class->setup_init($conf);
    $class->setup_network($conf);
    $class->set_hostname($conf);

    # fixme: what else ?
}

1;
