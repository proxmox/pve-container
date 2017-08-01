package PVE::LXC::Setup::SUSE;

use strict;
use warnings;

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;

    my $version = $os_release->{VERSION_ID};
    my $ostype = $os_release->{ID};
    my $setup_ct_getty_service;

    if ($version =~ m/^(\d+)\.(\d+)$/) {
	my ($major, $minor) = ($1, $2);
	if ($major >= 42) {
	    # OK
	    $setup_ct_getty_service = 1;
	} elsif ($major == 13 && $minor <= 2) {
	    # OK
	    $setup_ct_getty_service = 1 if $minor >= 2;
	} elsif ($ostype eq 'sles' && $major == 12) {
	    # OK - shares base with LEAP (42)
	    $setup_ct_getty_service = 1;
	} else {
	    die "unsupported suse release '$version'\n";
	}
    } elsif ($version =~ m/^(\d{4})(\d{2})(\d{2})$/) {
	my ($year, $month, $day) = ($1, $2, $3);
	if ($year >= 2017 && $month <= 12 && $day <= 31) {
	    # OK
	    $setup_ct_getty_service = 1;
	} else {
	    die "unsupported suse tumbleweed release '$version'\n";
	}
    } else {
	die "unrecognized suse release";
    }

    my $self = { conf => $conf, rootdir => $rootdir, version => $version, os_release => $os_release };
    $self->{setup_ct_getty_service} = 1 if $setup_ct_getty_service;

    $conf->{ostype} = 'opensuse';

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;

    $self->setup_securetty($conf);
}

sub setup_init {
    my ($self, $conf) = @_;

    if ($self->{setup_ct_getty_service}) {
	$self->setup_container_getty_service($conf);
    }
    $self->setup_systemd_console($conf);
}

sub setup_network {
    my ($self, $conf) = @_;

    my ($gw, $gw6);

    $self->ct_make_path('/etc/sysconfig/network');

    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	next if !$d->{name};

	my $filename = "/etc/sysconfig/network/ifcfg-$d->{name}";
	my $routefile = "/etc/sysconfig/network/ifroute-$d->{name}";
	my $routes = '';

	my @DHCPMODES = ('static', 'dhcp4', 'dhcp6', 'dhcp');
	my ($NONE, $DHCP4, $DHCP6, $BOTH) = (0, 1, 2, 3);
	my $dhcp = $NONE;
	my @addrs = ();

	my $data = '';
	my $is_configured = 0;

	if ($d->{ip} && $d->{ip} ne 'manual') {
	    $is_configured = 1;
	    if ($d->{ip} eq 'dhcp') {
		$dhcp |= $DHCP4;
	    } else {
		push @addrs, $d->{ip};
		if (defined($d->{gw})) {
		    if (!PVE::Network::is_ip_in_cidr($d->{gw}, $d->{ip}, 4)) {
			$routes .= "$d->{gw} 0.0.0.0 255.255.255.255 $d->{name}\n";
		    }
		    $routes .= "default $d->{gw} 0.0.0.0 $d->{name}\n";
		}
	    }
	}

	if ($d->{ip6} && $d->{ip6} ne 'manual') {
	    $is_configured = 1;
	    if ($d->{ip6} eq 'auto') {
		# FIXME: Not sure what to do here...
	    } elsif ($d->{ip6} eq 'dhcp') {
		$dhcp |= $DHCP6;
	    } else {
		push @addrs, $d->{ip6};
		if (defined($d->{gw6})) {
		    if (!PVE::Network::is_ip_in_cidr($d->{gw6}, $d->{ip6}, 6) &&
		        !PVE::Network::is_ip_in_cidr($d->{gw6}, 'fe80::/10', 6)) {
			$routes .= "$d->{gw6}/128 - - $d->{name}\n";
		    }
		    $routes .= "default $d->{gw6} - $d->{name}\n";
		}
	    }
	}

	if (@addrs > 1) {
	    for my $i (1..@addrs) {
		$data .= "IPADDR_${i}=$addrs[$i-1]\n";
	    }
	} elsif (@addrs) {
	    $data .= "IPADDR=$addrs[0]\n";
	} else {
	    # check for non-manual config with no dhcp and no addresses
	    next if $is_configured && $dhcp == $NONE;
	}

	$data = "STARTMODE=" . ($is_configured ? 'onboot' : 'manual') . "\n"
	      . "BOOTPROTO=$DHCPMODES[$dhcp]\n"
	      . $data;
	$self->ct_file_set_contents($filename, $data);

	# To keep user-defined routes in route-$iface we mark ours:
	$self->ct_modify_file($routefile, $routes, delete => 1, prepend => 1);
    }
}

1;
