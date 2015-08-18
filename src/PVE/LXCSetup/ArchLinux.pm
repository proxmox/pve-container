package PVE::LXCSetup::ArchLinux;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXCSetup::Base;

use base qw(PVE::LXCSetup::Base);

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
    # ArchLinux doesn't come with any particular predefined and enabled
    # networking, so it probably makes sense to do the equivalent of
    # 'systemctl enable systemd-networkd', since that's what we're configuring
    # in setup_network

    my $rootdir = $self->{rootdir};

    # systemctl enable systemd-networkd
    make_path("$rootdir/etc/systemd/system/multi-user.target.wants");
    make_path("$rootdir/etc/systemd/system/socket.target.wants");
    symlink "/usr/lib/systemd/system/systemd-networkd.service",
            "$rootdir/etc/systemd/system/multi-user.target.wants/systemd-networkd.service";
    symlink "/usr/lib/systemd/system/systemd-networkd.socket",
            "$rootdir/etc/systemd/system/socket.target.wants/systemd-networkd.socket";
}

sub setup_init {
    # Nothing to do
}

sub setup_network {
    my ($self, $conf) = @_;

    $self->setup_systemd_networkd($conf);
}

1;
