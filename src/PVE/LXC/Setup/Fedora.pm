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

sub setup_network {
    my ($self, $conf) = @_;

    # systemd-networkd is default in fedora-templates from upstream since
    # 25, however quite a few workarounds were posted in the forum, recommending
    # to start the (legacy) network.service via /etc/rc.local for fedora > 25.
    # /etc/sysconfig/network is not present in the templates for fedora > 25.
    # use its presence to decide, whether to configure the legacy config
    # additionally for 25, 26, 27.

    my $sysconfig_used = $self->ct_file_exists("/etc/sysconfig/network");

    my $version = $self->{version};

    my $setup_sysconfig = ($version <= 24 || ($self->{version} <= 27 && $sysconfig_used));
    my $setup_systemd = ($self->{version} >= 25);

    $self->SUPER::setup_network($conf) if $setup_sysconfig;
    $self->SUPER::setup_systemd_networkd($conf) if $setup_systemd;
}
1;
