package PVE::LXC::Setup::Debian;

use strict;
use warnings;
use Data::Dumper;
use PVE::Tools qw($IPV6RE);
use PVE::LXC;
use PVE::Network;
use File::Path;

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $version = PVE::Tools::file_read_firstline("$rootdir/etc/debian_version");

    die "unable to read version info\n" if !defined($version);

    # translate testing version names
    $version = 9.1 if $version eq 'stretch/sid';
    $version = 10 if $version eq 'buster/sid';

    die "unable to parse version info '$version'\n"
	if $version !~ m/^(\d+(\.\d+)?)(\.\d+)?/;

    $version = $1;

    die "unsupported debian version '$version'\n"
	if !($version >= 4 && $version <= 10);

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "debian";

    return bless $self, $class;
}

# Debian doesn't support the /dev/lxc/ subdirectory.
sub devttydir {
    return '';
}

sub setup_init {
    my ($self, $conf) = @_;

    my $systemd = $self->ct_readlink('/sbin/init');
    if (defined($systemd) && $systemd =~ m@/systemd$@) {
	$self->setup_container_getty_service($conf);
    }

    my $filename = "/etc/inittab";
    return if !$self->ct_file_exists($filename);

    my $ttycount =  PVE::LXC::Config->get_tty_count($conf);
    my $inittab = $self->ct_file_get_contents($filename);

    my @lines = grep {
	    # remove getty lines
	    !/^\s*\d+:\d*:[^:]*:.*getty/ &&
	    # remove power lines
	    !/^\s*p[fno0]:/
	} split(/\n/, $inittab);

    $inittab = join("\n", @lines) . "\n";

    $inittab .= "p0::powerfail:/sbin/init 0\n";

    my $version = $self->{version};
    for (my $id = 1; $id <= $ttycount; $id++) {
	next if $id == 7; # reserved for X11
	my $levels = ($id == 1) ? '2345' : '23';
	if ($version < 7) {
	    $inittab .= "$id:$levels:respawn:/sbin/getty -L 38400 tty$id\n";
	} else {
	    $inittab .= "$id:$levels:respawn:/sbin/getty --noclear 38400 tty$id\n";
	}
    }

    $self->ct_file_set_contents($filename, $inittab);
}

sub remove_gateway_scripts {
    my ($attr) = @_;
    my $length = scalar(@$attr);

    my $found_section = 0;
    my $keep = 1;
    @$attr = grep {
	if ($_ eq '# --- BEGIN PVE ---') {
	    $found_section = 1;
	    $keep = 0;
	    0; # remove this line
	} elsif ($_ eq '# --- END PVE ---') {
	    $found_section = 1;
	    $keep = 1;
	    0; # remove this line
	} else {
	    $keep;
	}
    } @$attr;

    return if $found_section;
    # XXX: To deal with existing setups we perform two types of removal for
    # now. Newly started containers have their routing sections marked with
    # begin/end comments. For older containers we perform a strict matching on
    # the routing rules we added. We can probably remove this part at some point
    # when it is unlikely that old debian setups are still around.

    for (my $i = 0; $i < $length-3; ++$i) {
	next if $attr->[$i+0] !~ m@^\s*post-up\s+ip\s+route\s+add\s+(\S+)\s+dev\s+(\S+)$@;
	my ($ip, $dev) = ($1, $2);
	if ($attr->[$i+1] =~ m@^\s*post-up\s+ip\s+route\s+add\s+default\s+via\s+(\S+)\s+dev\s+(\S+)$@ &&
	    ($ip eq $1 && $dev eq $2) &&
	    $attr->[$i+2] =~ m@^\s*pre-down\s+ip\s+route\s+del\s+default\s+via\s+(\S+)\s+dev\s+(\S+)$@ &&
	    ($ip eq $1 && $dev eq $2) &&
	    $attr->[$i+3] =~ m@^\s*pre-down\s+ip\s+route\s+del\s+(\S+)\s+dev\s+(\S+)$@ &&
	    ($ip eq $1 && $dev eq $2))
	{
	    splice @$attr, $i, 4;
	    $length -= 4;
	    --$i;
	}
    }
}

sub make_gateway_scripts {
    my ($ifname, $gw) = @_;
    return <<"SCRIPTS";
# --- BEGIN PVE ---
\tpost-up ip route add $gw dev $ifname
\tpost-up ip route add default via $gw dev $ifname
\tpre-down ip route del default via $gw dev $ifname
\tpre-down ip route del $gw dev $ifname
# --- END PVE ---
SCRIPTS
}

sub setup_network {
    my ($self, $conf) = @_;

    my $networks = {};
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	if ($d->{name}) {
	    my $net = {};
	    my $cidr;
	    if (defined($d->{ip})) {
		if ($d->{ip} =~ /^(?:dhcp|manual)$/) {
		    $net->{address} = $d->{ip};
		} else {
		    my $ipinfo = PVE::LXC::parse_ipv4_cidr($d->{ip});
		    $net->{address} = $ipinfo->{address};
		    $net->{netmask} = $ipinfo->{netmask};
		    $cidr = $d->{ip};
		}
	    }
	    if (defined($d->{'gw'})) {
		$net->{gateway} = $d->{'gw'};
		if (defined($cidr) && !PVE::Network::is_ip_in_cidr($d->{gw}, $cidr, 4)) {
		    # gateway is not reachable, need an extra route
		    $net->{needsroute} = 1;
		}
	    }
	    $cidr = undef;
	    if (defined($d->{ip6})) {
		if ($d->{ip6} =~ /^(?:auto|dhcp|manual)$/) {
		    $net->{address6} = $d->{ip6};
		} elsif ($d->{ip6} !~ /^($IPV6RE)\/(\d+)$/) {
		    die "unable to parse ipv6 address/prefix\n";
		} else {
		    $net->{address6} = $1;
		    $net->{netmask6} = $2;
		    $cidr = $d->{ip6};
		}
	    }
	    if (defined($d->{'gw6'})) {
		$net->{gateway6} = $d->{'gw6'};
		if (defined($cidr) && !PVE::Network::is_ip_in_cidr($d->{gw6}, $cidr, 6) &&
		    !PVE::Network::is_ip_in_cidr($d->{gw6}, 'fe80::/10', 6)) {
		    # gateway is not reachable, need an extra route
		    $net->{needsroute6} = 1;
		}
	    }
	    $networks->{$d->{name}} = $net if keys %$net;
	}
    }

    return if !scalar(keys %$networks);

    my $filename = "/etc/network/interfaces";
    my $interfaces = "";

    my $section;

    my $done_auto = {};
    my $done_v4_hash = {};
    my $done_v6_hash = {};

    my $print_section = sub {
	return if !$section;

	my $ifname = $section->{ifname};
	my $net = $networks->{$ifname};

	if (!$done_auto->{$ifname}) {
	    $interfaces .= "auto $ifname\n";
	    $done_auto->{$ifname} = 1;
	}

	if ($section->{type} eq 'ipv4') {
	    $done_v4_hash->{$ifname} = 1;

	    if (!defined($net->{address})) {
		# no address => no iface line
	    } elsif ($net->{address} =~ /^(dhcp|manual)$/) {
		$interfaces .= "iface $ifname inet $1\n\n";
	    } else {
		$interfaces .= "iface $ifname inet static\n";
		$interfaces .= "\taddress $net->{address}\n" if defined($net->{address});
		$interfaces .= "\tnetmask $net->{netmask}\n" if defined($net->{netmask});

		remove_gateway_scripts($section->{attr});
		if (defined(my $gw = $net->{gateway})) {
		    if ($net->{needsroute}) {
			$interfaces .= make_gateway_scripts($ifname, $gw);
		    } else {
			$interfaces .= "\tgateway $gw\n";
		    }
		}
		foreach my $attr (@{$section->{attr}}) {
		    $interfaces .= "\t$attr\n";
		}
		$interfaces .= "\n";
	    }
	} elsif ($section->{type} eq 'ipv6') {
	    $done_v6_hash->{$ifname} = 1;

	    if (!defined($net->{address6})) {
		# no address => no iface line
	    } elsif ($net->{address6} =~ /^(auto|dhcp|manual)$/) {
		$interfaces .= "iface $ifname inet6 $1\n\n";
	    } else {
		$interfaces .= "iface $ifname inet6 static\n";
		$interfaces .= "\taddress $net->{address6}\n" if defined($net->{address6});
		$interfaces .= "\tnetmask $net->{netmask6}\n" if defined($net->{netmask6});
		remove_gateway_scripts($section->{attr});
		if (defined(my $gw = $net->{gateway6})) {
		    if ($net->{needsroute6}) {
			$interfaces .= make_gateway_scripts($ifname, $gw);
		    } else {
			$interfaces .= "\tgateway $net->{gateway6}\n" if defined($net->{gateway6});
		    }
		}
		foreach my $attr (@{$section->{attr}}) {
		    $interfaces .= "\t$attr\n";
		}
		$interfaces .= "\n";
	    }
	} else {
	    die "unknown section type '$section->{type}'";
	}

	$section = undef;
    };

    if (my $fh = $self->ct_open_file_read($filename)) {
	while (defined (my $line = <$fh>)) {
	    chomp $line;
	    if ($line =~ m/^# --- (?:BEGIN|END) PVE ---/) {
		# Include markers in the attribute section so
		# remove_gateway_scripts() can find them.
		push @{$section->{attr}}, $line if $section;
		next;
	    }
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
	    # Handle 'auto'
	    if ($line =~ m/^\s*auto\s*(.*)$/) {
		foreach my $iface (split(/\s+/, $1)) {
		    $done_auto->{$iface} = 1;
		}
		&$print_section();
	        $interfaces .= "$line\n";
	        next;
	    }
	    # Handle other section delimiters:
	    if ($line =~ m/^\s*(?:mapping\s
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

    my $need_separator = length($interfaces) && ($interfaces !~ /\n\n$/);
    foreach my $ifname (sort keys %$networks) {
	my $net = $networks->{$ifname};

	if (!$done_v4_hash->{$ifname} && defined($net->{address})) {
	    if ($need_separator) { $interfaces .= "\n"; $need_separator = 0; };
	    $section = { type => 'ipv4', ifname => $ifname, attr => []};
	    &$print_section();
	}
	if (!$done_v6_hash->{$ifname} && defined($net->{address6})) {
	    if ($need_separator) { $interfaces .= "\n"; $need_separator = 0; };
	    $section = { type => 'ipv6', ifname => $ifname, attr => []};
	    &$print_section();
	}
    }

    # older templates (< Debian 8) do not configure the loopback interface
    # if not explicitly told to do so
    if (!$done_auto->{lo}) {
	$interfaces = "auto lo\niface lo inet loopback\n" .
	              "iface lo inet6 loopback\n\n" .
	              $interfaces;
    }

    $self->ct_file_set_contents($filename, $interfaces);
}

1;
