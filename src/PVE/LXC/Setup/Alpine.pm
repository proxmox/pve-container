package PVE::LXC::Setup::Alpine;

use strict;
use warnings;

use PVE::LXC;
use PVE::Network;
use File::Path;

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;
    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };
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
}

sub setup_init {
    # Nothing to do
}

sub setup_network {
    # Nothing to do
}

1;
