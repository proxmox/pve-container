package PVE::LXC::Setup::Fedora;

use strict;
use warnings;

use PVE::LXC::Setup::CentOS;

use base qw(PVE::LXC::Setup::CentOS);

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;

    my $version = $os_release->{VERSION_ID};
    die "unsupported Fedora release '$version'\n" if !($version >= 22 && $version <= 40);

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "fedora";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
    $self->setup_securetty($conf);
    $self->ct_unlink('/etc/systemd/system/getty@.service');

    $self->remove_lxc_name_from_etc_hosts();
}

sub setup_init {
    my ($self, $conf) = @_;
    $self->setup_container_getty_service($conf);

    my $version = $self->{version};

    if ($version >= 37) {
	# this only affects the first-boot (if no /etc/machien-id exists).
	$self->setup_systemd_preset({
	    # systemd-networkd is disabled by the preset in >=37 in favor of
	    # NetworkManager, reenable it, since we make use of it.
	    'systemd-networkd.service' => 0,
	});
    }
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

    my $setup_sysconfig = ($version <= 24 || ($version <= 27 && $sysconfig_used));
    my $setup_systemd = ($version >= 25);

    $self->SUPER::setup_network($conf) if $setup_sysconfig;
    $self->SUPER::setup_systemd_networkd($conf) if $setup_systemd;
}
1;
