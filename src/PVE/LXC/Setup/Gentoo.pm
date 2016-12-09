package PVE::LXC::Setup::Gentoo;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $version = PVE::Tools::file_read_firstline("$rootdir/etc/gentoo-release");
    die "unable to read version info\n" if !defined($version);
    if ($version =~ /^gentoo base system release (.*)$/i) {
	$version = $1;
    } else {
	die "unrecognized gentoo version: $version\n";
    }

    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };

    $conf->{ostype} = "gentoo";

    return bless $self, $class;
}

# Gentoo doesn't support the /dev/lxc/ subdirectory
sub devttydir {
    return '';
}

sub template_fixup {
    my ($self, $conf) = @_;
    $self->setup_securetty($conf);
}

sub setup_init {
    my ($self, $conf) = @_;

    my $filename = "/etc/inittab";
    my $ttycount =  PVE::LXC::Config->get_tty_count($conf);
    my $inittab = $self->ct_file_get_contents($filename);

    my @lines = grep {
	    # remove getty lines
	    !/^\s*c?\d+:\d*:[^:]*:.*getty/
    } split(/\n/, $inittab);

    $inittab = join("\n", @lines) . "\n";

    for (my $id = 1; $id <= $ttycount; $id++) {
	next if $id == 7; # reserved for X11
	$inittab .= "$id\::respawn:/sbin/agetty 38400 tty$id\n";
    }

    $self->ct_file_set_contents($filename, $inittab);
}

sub setup_network {
    my ($self, $conf) = @_;

    # Gentoo's /etc/conf.d/net is supposed to only contains variables, but is
    # in fact sourced by a shell, so reading out existing modules/config values
    # is pretty inconvenient.
    # We SHOULD check for whether iproute2 or ifconfig is already being used,
    # but for now we just assume ifconfig (since they also state iproute2 might
    # not be available in a default setup, though the templates usually do have
    # it installed - we might just get away with an if/else clause to insert
    # ifconfig/iproute2 syntax as needed, that way we don't need to parse this
    # file even to support both...)

    my %modules = (ifconfig => 1);

    my $data = '';
    my %up;

    my $filename = "/etc/conf.d/net";

    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	my $name = $d->{name};
	next if !$name;

	my $has_ipv4 = 0;
	my $has_ipv6 = 0;

	my $config = '';
	my $routes = '';

	if (defined(my $ip = $d->{ip})) {
	    if ($ip eq 'dhcp') {
		#$modules{dhclient} = 1; # Well, we could...
		$config .= "dhcp\n";
		$up{$name} = 1;
	    } elsif ($ip ne 'manual') {
		$has_ipv4 = 1;
		$config .= "$ip\n";
		$up{$name} = 1;
	    }
	}
	if (defined(my $gw = $d->{gw})) {
	    if ($has_ipv4 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip}, 4)) {
		$routes .= "-host $gw dev $name\n";
	    }
	    $routes .= "default gw $gw\n";
	    $up{$name} = 1;
	}

	if (defined(my $ip = $d->{ip6})) {
	    if ($ip eq 'dhcp') {
		# FIXME: The default templates seem to only ship busybox' udhcp
		# client which means we're in the same boat as alpine linux.
		# They also don't provide dhcpv6-only at all - for THAT however
		# there are patches from way back in 2013 (bug#450326 on
		# gentoo.org's netifrc)... but whatever, # that's only 10 years
		# after the RFC3315 release (DHCPv6).
		#
		# So no dhcpv6(-only) setups here for now.

		#$modules{dhclientv6} = 1;
		#$config .= "dhcpv6\n";
		#$up{$name} = 1;
	    } elsif ($ip ne 'manual') {
		$has_ipv6 = 1;
		$config .= "$ip\n";
		$up{$name} = 1;
	    }
	}
	if (defined(my $gw = $d->{gw6})) {
	    if ($has_ipv6 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip6}, 4)) {
		$routes .= "-6 -host $gw dev $name\n";
	    }
	    $routes .= "-6 default gw $gw\n";
	    $up{$name} = 1;
	}

	chomp $config;
	chomp $routes;
	$data .= "config_$name=\"$config\"\n" if $config;
	$data .= "routes_$name=\"$routes\"\n" if $routes;
    }

    $data = "modules=\"\$modules " . join(' ', sort keys %modules) . "\"\n" . $data;

    # We replace the template's default file...
    $self->ct_modify_file($filename, $data, replace => 1);

    foreach my $iface (keys %up) {
	$self->ct_symlink("net.lo", "/etc/init.d/net.$iface");
    }
}

sub set_hostname {
    my ($self, $conf) = @_;

    my $hostname = $conf->{hostname} || 'localhost';

    my $namepart = ($hostname =~ s/\..*$//r);

    my $hostname_fn = "/etc/conf.d/hostname";

    my $oldname = 'localhost';
    my $fh = $self->ct_open_file_read($hostname_fn);
    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ /^\s*(#.*)?$/;
	if ($line =~ /^\s*hostname=("[^"]*"|'[^']*'|\S*)\s*$/) {
	    $oldname = $1;
	    last;
	}
    }
    $fh->close();

    my ($ipv4, $ipv6) = PVE::LXC::get_primary_ips($conf);
    my $hostip = $ipv4 || $ipv6;

    my ($searchdomains) = $self->lookup_dns_conf($conf);

    $self->update_etc_hosts($hostip, $oldname, $hostname, $searchdomains);

    # This is supposed to contain only the hostname, so we just replace the
    # file.
    $self->ct_file_set_contents($hostname_fn, "hostname=\"$namepart\"\n");
}

1;
