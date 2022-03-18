package PVE::LXC::Setup::NixOS;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };

    $conf->{ostype} = "nixos";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
}

sub setup_network {
    my ($self, $conf) = @_;

    $self->setup_systemd_networkd($conf);
}

sub set_timezone {
    my ($self, $conf) = @_;
}

sub setup_init {
    my ($self, $conf) = @_;
}

1;
