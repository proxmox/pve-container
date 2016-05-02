package PVE::LXC::Setup::Alpine;

use strict;
use warnings;

use PVE::LXC;
use PVE::Network;
use File::Path;

use PVE::LXC::Setup::Base;
use PVE::LXC::Setup::Debian;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $version = PVE::Tools::file_read_firstline("$rootdir/etc/alpine-release");

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };
    $conf->{ostype} = "alpine";
    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
    my $rootdir = $self->{rootdir};
    # enable networking service
    $self->ct_symlink('/etc/init.d/networking',
                      '/etc/runlevels/boot/networking');
    # fixup any symlinks
    $self->ct_symlink('/etc/init.d/bootmisc',
                      '/etc/runlevels/boot/bootmisc');
    $self->ct_symlink('/etc/init.d/hostname',
                      '/etc/runlevels/boot/hostname');
    # fix stop system
    $self->ct_symlink('/etc/init.d/killprocs',
                      '/etc/runlevels/shutdown/killprocs');
    $self->ct_symlink('/etc/init.d/savecache',
                      '/etc/runlevels/shutdown/savecache');

    $self->setup_securetty($conf, qw(lxc/console lxc/tty1 lxc/tty2 lxc/tty3 lxc/tty4));
}

sub setup_init {
    # Nothing to do
}

sub setup_network {
    # Network is debian compatible, but busybox' udhcpc6 is unfinished
    my ($self, $conf) = @_;

    # XXX: udhcpc6 in busybox is broken; once a working alpine release comes
    # we can remove this bit.
    #
    # Filter out ipv6 dhcp and turn it into 'manual' so they see what's up.
    my $netconf = {};
    my $networks = {};
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $netstring = $conf->{$k};
	# check for dhcp6:
	my $d = PVE::LXC::Config->parse_lxc_network($netstring);
	if (defined($d->{ip6}) && $d->{ip6} eq 'dhcp') {
	    $d->{ip6} = 'manual';
	    $netstring = PVE::LXC::Config->print_lxc_network($d);
	}
	$netconf->{$k} = $netstring;
    }

    PVE::LXC::Setup::Debian::setup_network($self, $netconf);
}

1;
