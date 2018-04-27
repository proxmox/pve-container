package PVE::LXC::Setup::Fedora;

use strict;
use warnings;

use PVE::LXC::Setup::CentOS;

use base qw(PVE::LXC::Setup::CentOS);

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;

    my $version = $os_release->{VERSION_ID};
    die "unsupported fedora release\n" if !($version >= 22 && $version <= 28);

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "fedora";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
    $self->setup_securetty($conf);
    $self->ct_unlink('/etc/systemd/system/getty@.service');
}

sub setup_init {
    my ($self, $conf) = @_;
    $self->setup_container_getty_service($conf);
}

1;
