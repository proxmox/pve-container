package PVE::LXC::Setup::OpenEuler;

use strict;
use warnings;

use PVE::LXC::Setup::CentOS;
use base qw(PVE::LXC::Setup::CentOS);

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;

    my $version = $os_release->{VERSION_ID};
    # we cannot really win anything by actively dying on newer versions so only check lower boundary.
    die "unsupported openEuler release '$version'\n" if !defined($version) || $version < 24;

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "openeuler";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;

    $self->remove_lxc_name_from_etc_hosts();
}

sub setup_init {
    my ($self, $conf) = @_;
    $self->setup_container_getty_service($conf);
    $self->setup_systemd_preset();
}

1;
