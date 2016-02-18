package PVE::LXC::Setup::SUSE;

use strict;
use warnings;

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $release = eval { -f "$rootdir/etc/SuSE-release"
                   ? PVE::Tools::file_get_contents("$rootdir/etc/SuSE-release")
                   : PVE::Tools::file_get_contents("$rootdir/etc/SuSE-brand") };
    die "unable to read version info\n" if $@;

    my $version;

    # Fixme: not sure whether the minor part is optional.
    if ($release =~ m/^\s*VERSION\s*=\s*(\d+)(?:\.(\d+))?\s*$/m) {
	$version = "$1.$2";
	# 13.2 needs an updated AppArmor profile (in lxc *after* 2.0.0.beta2)
	if ($1 != 13 || ($2//0) > 2) {
	    die "unsupported suse release '$version'\n";
	}
    } else {
	die "unrecognized suse release";
    }

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = 'opensuse';

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;

    $self->setup_securetty($conf, qw(lxc/console lxc/tty1 lxc/tty2 lxc/tty3 lxc/tty4));
}

sub setup_init {
    my ($self, $conf) = @_;

    if ($self->{version} >= 13.2) {
	$self->setup_container_getty_service();
    }
    $self->setup_systemd_console($conf);
}

sub setup_network {
    my ($self, $conf) = @_;

    my ($gw, $gw6);

    $self->ct_make_path('/etc/sysconfig/network');

    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = PVE::LXC::parse_lxc_network($conf->{$k});
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
		    if (!PVE::Network::is_ip_in_cidr($d->{gw6}, $d->{ip6}, 6)) {
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
	my $head = "# --- BEGIN PVE ROUTES ---\n";
	my $tail = "# --- END PVE ROUTES ---\n";
	$self->ct_modify_file_head_portion($routefile, $head, $tail, $routes);
    }
}

1;
