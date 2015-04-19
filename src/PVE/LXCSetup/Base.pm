package PVE::LXCSetup::Base;

use strict;
use warnings;

sub change_hostname  {
    my ($etc_hosts_data, $hostip, $oldname, $newname) = @_;

    # fixme: searchdomain ?
    
    my $done = 0;

    my @lines;
    
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
		    push @lines, "$ip $newname";
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
	    push @lines, "$hostip $newname";
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
}

sub set_hostname {
    my ($class, $conf) = @_;
    
    my $hostname = $conf->{'lxc.utsname'} || 'debian';

    $hostname =~ s/\..*$//;

    my $rootfs = $conf->{'lxc.rootfs'};

    my $hostname_fn = "$rootfs/etc/hostname";
    
    my $oldname = PVE::Tools::file_read_firstline($hostname_fn) || 'debian';

    my $hosts_fn = "$rootfs/etc/hosts";
    my $etc_hosts_data = '';
    
    if (-f $hosts_fn) {
	$etc_hosts_data =  PVE::Tools::file_get_contents($hosts_fn);
    }

    my $hostip = undef; # fixme;
    
    $etc_hosts_data = change_hostname($etc_hosts_data, $hostip, $oldname, $hostname);
  
    PVE::Tools::file_set_contents($hostname_fn, "$hostname\n");
    PVE::Tools::file_set_contents($hosts_fn, $etc_hosts_data);
}

sub post_create {
    my ($class, $conf) = @_;

    $class->set_hostname($conf);

    # fixme: what else (network, ...)
}

1;
