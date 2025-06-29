package PVE::LXC::Setup::ArchLinux;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXC::Setup::Base;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    # /etc/arch-release exists, but it's empty
    #my $release = PVE::Tools::file_read_firstline("$rootdir/etc/arch-release");
    #die "unable to read version info\n" if !defined($release);

    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };

    $conf->{ostype} = "archlinux";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;

    # edit /etc/securetty (enable login on console)
    $self->setup_securetty($conf);

    $self->remove_lxc_name_from_etc_hosts();
}

sub setup_init {
    my ($self, $conf) = @_;

    $self->setup_systemd_preset({
        # ArchLinux doesn't come with any particular predefined and enabled
        # networking, so it probably makes sense to do the equivalent of
        # 'systemctl enable systemd-networkd', since that's what we're configuring
        # in setup_network
        'systemd-networkd.service' => 1,
    });

    $self->setup_container_getty_service($conf);
}

sub setup_network {
    my ($self, $conf) = @_;

    $self->setup_systemd_networkd($conf);
}

1;
