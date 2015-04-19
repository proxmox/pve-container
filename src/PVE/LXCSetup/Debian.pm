package PVE::LXCSetup::Debian;

use strict;
use warnings;
use Data::Dumper;
use PVE::Tools;
use PVE::LXC;
use File::Path;

use PVE::LXCSetup::Base;

use base qw(PVE::LXCSetup::Base);

sub setup_network {
    my ($class, $conf) = @_;

    my $rootfs = $conf->{'lxc.rootfs'};

    my $networks = {};
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = $conf->{$k};
	if ($d->{name}) {
	    my $net = {};
	    if (defined($d->{ipv4})) {
		my $ipinfo = PVE::LXC::parse_ipv4_cidr($d->{ipv4});
		$net->{v4address} = $ipinfo->{address};
		$net->{v4netmask} = $ipinfo->{netmask};
	    }
	    if (defined($d->{'ipv4.gateway'})) {
		$net->{v4gateway} = $d->{'ipv4.gateway'};
	    }
	    if (defined($d->{ipv6})) {
		die "implement me";
	    }
	    $networks->{$d->{name}} = $net;
	}
    }

    return if !scalar(keys %$networks);

    my $filename = "$rootfs/etc/network/interfaces";
    my $data = {};
    my $order = [];
    my $interfaces = "";

    my $section;

    my $done_v4_hash = {};
    my $done_v6_hash = {};
    
    my $print_section = sub {
	my ($new) = @_;
	
	return if !$section;

	my $net = $networks->{$section->{ifname}};

	if ($section->{type} eq 'ipv4') {
	    $done_v4_hash->{$section->{ifname}} = 1;

	    $interfaces .= "auto $section->{ifname}\n" if $new;

	    if ($net->{v4address}) {
		$interfaces .= "iface $section->{ifname} inet static\n";
		$interfaces .= "\taddress $net->{v4address}\n" if defined($net->{v4address});
		$interfaces .= "\tnetmask $net->{v4netmask}\n" if defined($net->{v4netmask});
		$interfaces .= "\taddress $net->{v4gateway}\n" if defined($net->{v4gateway});
		foreach my $attr (@{$section->{attr}}) {
		    $interfaces .= "\t$attr\n";
		}
	    } else {
		$interfaces .= "iface $section->{ifname} inet manual\n";		
	    }
	    
	    $interfaces .= "\n";
	    
	} elsif ($section->{type} eq 'ipv6') {
	    $done_v6_hash->{$section->{ifname}} = 1;
	    
	    if ($net->{v6address}) {
		$interfaces .= "iface $section->{ifname} inet6 static\n";
		$interfaces .= "\taddress $net->{v6address}\n" if defined($net->{v6address});
		$interfaces .= "\tnetmask $net->{v6netmask}\n" if defined($net->{v6netmask});
		$interfaces .= "\taddress $net->{v6gateway}\n" if defined($net->{v6gateway});
		foreach my $attr (@{$section->{attr}}) {
		    $interfaces .= "\t$attr\n";
		}
	    }
	    
	    $interfaces .= "\n";	
	} else {
	    die "unknown section type '$section->{type}'";
	}

	$section = undef;
    };
	
    if (my $fh = IO::File->new($filename, "r")) {
	while (defined (my $line = <$fh>)) {
	    chomp $line;
	    if ($line =~ m/^#/) {
		$interfaces .= "$line\n";
		next;
	    }
	    if ($line =~ m/^\s*$/) {
		if ($section) {
		    &$print_section();
		} else {
		    $interfaces .= "$line\n";
		}
		next;
	    }
	    if ($line =~ m/^iface\s+(\S+)\s+inet\s+(\S+)\s*$/) {
		my $ifname = $1;
		if (!$networks->{$ifname}) {
		    $interfaces .= "$line\n";
		    next;
		}
		$section = { type => 'ipv4', ifname => $ifname, attr => []};
		next;
	    }
	    if ($line =~ m/^iface\s+(\S+)\s+inet6\s+(\S+)\s*$/) {
		my $ifname = $1;
		if (!$networks->{$ifname}) {
		    $interfaces .= "$line\n";
		    next;
		}
		$section = { type => 'ipv6', ifname => $ifname, attr => []};
		next;
	    }
	    if ($section && $line =~ m/^\s*((\S+)\s(.*))$/) {
		my ($adata, $aname) = ($1, $2);
		if ($aname eq 'address' || $aname eq 'netmask' ||
		    $aname eq 'gateway' || $aname eq 'broadcast') {
		    # skip
		} else {
		    push @{$section->{attr}}, $adata; 
		}
		next;
	    }
	    
	    $interfaces .= "$line\n";	    
	}
	&$print_section();
	
    }

    foreach my $ifname (sort keys %$networks) {
	my $net = $networks->{$ifname};
	if (!$done_v4_hash->{$ifname}) {
	    $section = { type => 'ipv4', ifname => $ifname, attr => []};
	    &$print_section(1);
	}
	if (!$done_v6_hash->{$ifname} && defined($net->{v6address})) {
	    $section = { type => 'ipv6', ifname => $ifname, attr => []};
	    &$print_section(1);
	}
    }
    
    PVE::Tools::file_set_contents($filename, $interfaces);
}

1;
