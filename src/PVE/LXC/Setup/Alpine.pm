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

# Alpine doesn't support the /dev/lxc/ subdirectory.
sub devttydir {
    return '';
}

sub template_fixup {
    my ($self, $conf) = @_;

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

    $self->setup_securetty($conf);
}

sub setup_init {
    my ($self, $conf) = @_;

    my $filename = "/etc/inittab";
    return if !$self->ct_file_exists($filename);

    my $ttycount =  PVE::LXC::Config->get_tty_count($conf);
    my $inittab = $self->ct_file_get_contents($filename);

    my @lines = grep {
	    # remove getty lines
	    !/^\s*tty\d+:\d*:[^:]*:.*getty/
    } split(/\n/, $inittab);

    $inittab = join("\n", @lines) . "\n";

    for (my $id = 1; $id <= $ttycount; $id++) {
	next if $id == 7; # reserved for X11
	$inittab .= "tty$id\::respawn:/sbin/getty 38400 tty$id\n";
    }

    $self->ct_file_set_contents($filename, $inittab);
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
