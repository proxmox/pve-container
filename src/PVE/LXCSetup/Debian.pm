package PVE::LXCSetup::Debian;

use strict;
use warnings;
use Data::Dumper;
use PVE::Tools qw($IPV6RE);
use PVE::LXC;
use File::Path;

use PVE::LXCSetup::Base;

use base qw(PVE::LXCSetup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $version = PVE::Tools::file_read_firstline("$rootdir/etc/debian_version");

    die "unable to read version info\n" if !defined($version);

    die "unable to parse version info\n"
	if $version !~ m/^(\d+(\.\d+)?)(\.\d+)?/;

    $version = $1;

    die "unsupported debian version '$version'\n" 
	if !($version >= 6 && $version < 9);

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "debian";

    return bless $self, $class;
}

my $default_inittab = <<__EOD__;

# The default runlevel.
id:2:initdefault:

# Boot-time system configuration/initialization script.
# This is run first except when booting in emergency (-b) mode.
si::sysinit:/etc/init.d/rcS

# /etc/init.d executes the S and K scripts upon change
# of runlevel.
#
# Runlevel 0 is halt.
# Runlevel 1 is single-user.
# Runlevels 2-5 are multi-user.
# Runlevel 6 is reboot.

l0:0:wait:/etc/init.d/rc 0
l1:1:wait:/etc/init.d/rc 1
l2:2:wait:/etc/init.d/rc 2
l3:3:wait:/etc/init.d/rc 3
l4:4:wait:/etc/init.d/rc 4
l5:5:wait:/etc/init.d/rc 5
l6:6:wait:/etc/init.d/rc 6
# Normally not reached, but fallthrough in case of emergency.
z6:6:respawn:/sbin/sulogin

# What to do when CTRL-ALT-DEL is pressed.
ca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now

# What to do when the power fails/returns.
p0::powerfail:/sbin/init 0

# /sbin/getty invocations for the runlevels.
#
# The "id" field MUST be the same as the last
# characters of the device (after "tty").
#
# Format:
#  <id>:<runlevels>:<action>:<process>
#
__EOD__

sub setup_init {
    my ($self, $conf) = @_;

    my $rootdir = $self->{rootdir};

    my $filename = "$rootdir/etc/inittab";

    if (-f $filename) {
	my $inittab = $default_inittab;

	my $ttycount = defined($conf->{'tty'}) ? $conf->{'tty'} : 4;
	for (my $i = 1; $i <= $ttycount; $i++) {
	    next if $i == 7; # reserved for X11
	    my $levels = ($i == 1) ? '2345' : '23';
	    if ($self->{version} < 7) {
		$inittab .= "$i:$levels:respawn:/sbin/getty -L 38400 tty$i\n";
	    } else {
		$inittab .= "$i:$levels:respawn:/sbin/getty --noclear 38400 tty$i\n";
	    }
	}
	
	PVE::Tools::file_set_contents($filename, $inittab);
    }
}

sub setup_network {
    my ($self, $conf) = @_;

    my $rootdir = $self->{rootdir};

    my $networks = {};
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = PVE::LXC::parse_lxc_network($conf->{$k});
	if ($d->{name}) {
	    my $net = {};
	    if (defined($d->{ip})) {
		if ($d->{ip} =~ /^(?:dhcp|manual)$/) {
		    $net->{address} = $d->{ip};
		} else {
		    my $ipinfo = PVE::LXC::parse_ipv4_cidr($d->{ip});
		    $net->{address} = $ipinfo->{address};
		    $net->{netmask} = $ipinfo->{netmask};
		}
	    }
	    if (defined($d->{'gw'})) {
		$net->{gateway} = $d->{'gw'};
	    }
	    if (defined($d->{ip6})) {
		if ($d->{ip6} =~ /^(?:auto|dhcp|manual)$/) {
		    $net->{address6} = $d->{ip6};
		} elsif ($d->{ip6} !~ /^($IPV6RE)\/(\d+)$/) {
		    die "unable to parse ipv6 address/prefix\n";
		} else {
		    $net->{address6} = $1;
		    $net->{netmask6} = $2;
		}
	    }
	    if (defined($d->{'gw6'})) {
		$net->{gateway6} = $d->{'gw6'};
	    }
	    $networks->{$d->{name}} = $net if keys %$net;
	}
    }

    return if !scalar(keys %$networks);

    my $filename = "$rootdir/etc/network/interfaces";
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

	    if ($net->{address} =~ /^(dhcp|manual)$/) {
		$interfaces .= "iface $section->{ifname} inet $1\n";
	    } elsif ($net->{address}) {
		$interfaces .= "iface $section->{ifname} inet static\n";
		$interfaces .= "\taddress $net->{address}\n" if defined($net->{address});
		$interfaces .= "\tnetmask $net->{netmask}\n" if defined($net->{netmask});
		$interfaces .= "\tgateway $net->{gateway}\n" if defined($net->{gateway});
		foreach my $attr (@{$section->{attr}}) {
		    $interfaces .= "\t$attr\n";
		}
	    }
	    
	    $interfaces .= "\n";
	    
	} elsif ($section->{type} eq 'ipv6') {
	    $done_v6_hash->{$section->{ifname}} = 1;
	    
	    if ($net->{address6} =~ /^(auto|dhcp|manual)$/) {
		$interfaces .= "iface $section->{ifname} inet6 $1\n";
	    } elsif ($net->{address6}) {
		$interfaces .= "iface $section->{ifname} inet6 static\n";
		$interfaces .= "\taddress $net->{address6}\n" if defined($net->{address6});
		$interfaces .= "\tnetmask $net->{netmask6}\n" if defined($net->{netmask6});
		$interfaces .= "\tgateway $net->{gateway6}\n" if defined($net->{gateway6});
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
	    if ($line =~ m/^\s*iface\s+(\S+)\s+inet\s+(\S+)\s*$/) {
		my $ifname = $1;
		&$print_section(); # print previous section
		if (!$networks->{$ifname}) {
		    $interfaces .= "$line\n";
		    next;
		}
		$section = { type => 'ipv4', ifname => $ifname, attr => []};
		next;
	    }
	    if ($line =~ m/^\s*iface\s+(\S+)\s+inet6\s+(\S+)\s*$/) {
		my $ifname = $1;
		&$print_section(); # print previous section
		if (!$networks->{$ifname}) {
		    $interfaces .= "$line\n";
		    next;
		}
		$section = { type => 'ipv6', ifname => $ifname, attr => []};
		next;
	    }
	    # Handle other section delimiters:
	    if ($line =~ m/^\s*(?:mapping\s
	                         |auto\s
	                         |allow-
	                         |source\s
	                         |source-directory\s
	                       )/x) {
	        &$print_section();
	        $interfaces .= "$line\n";
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

    my $need_separator = 1;
    foreach my $ifname (sort keys %$networks) {
	my $net = $networks->{$ifname};
	
	if (!$done_v4_hash->{$ifname}) {
	    if ($need_separator) { $interfaces .= "\n"; $need_separator = 0; };	    
	    $section = { type => 'ipv4', ifname => $ifname, attr => []};
	    &$print_section(1);
	}
	if (!$done_v6_hash->{$ifname} && defined($net->{address6})) {
	    if ($need_separator) { $interfaces .= "\n"; $need_separator = 0; };	    
	    $section = { type => 'ipv6', ifname => $ifname, attr => []};
	    &$print_section(1);
	}
    }
    
    PVE::Tools::file_set_contents($filename, $interfaces);
}

1;
