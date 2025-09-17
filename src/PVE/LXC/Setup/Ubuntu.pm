package PVE::LXC::Setup::Ubuntu;

use strict;
use warnings;

use PVE::Tools;
use PVE::LXC;
use PVE::RESTEnvironment qw(log_warn);

use File::Path;

use PVE::LXC::Setup::Debian;

use base qw(PVE::LXC::Setup::Debian);

my $known_versions = {
    '26.04' => 1, # r LTS
    '25.10' => 1, # questing
    '25.04' => 1, # plucky
    '24.10' => 1, # oracular
    '24.04' => 1, # noble LTS
    '23.10' => 1, # mantic
    '23.04' => 1, # lunar
    '22.10' => 1, # kinetic
    '22.04' => 1, # jammy LTS
    '21.10' => 1, # impish
    '21.04' => 1, # hirsute
    '20.10' => 1, # groovy
    '20.04' => 1, # focal LTS
    '19.10' => 1, # eoan
    '19.04' => 1, # disco
    '18.10' => 1, # cosmic
    '18.04' => 1, # bionic LTS
    '17.10' => 1, # artful
    '17.04' => 1, # zesty
    # TODO: actively drop below entries that ship with systemd, as their version is too old for CGv2
    '16.10' => 1, # yakkety
    '16.04' => 1, # xenial LTS
    '15.10' => 1, # wily
    '15.04' => 1, # vivid
    '14.04' => 1, # trusty LTS
    '12.04' => 1, # precise LTS
};

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $lsb_fn = "$rootdir/etc/lsb-release";
    my $lsbinfo = PVE::Tools::file_get_contents($lsb_fn);

    die "got unknown DISTRIB_ID\n" if $lsbinfo !~ m/^DISTRIB_ID=Ubuntu$/mi;

    my $version;
    if ($lsbinfo =~ m/^DISTRIB_RELEASE=(\d+\.\d+)$/mi) {
        $version = $1;
    }

    die "unable to read version info\n" if !defined($version);

    if ($known_versions->{$version}) {
        # OK, fully known version.
    } elsif ($version =~ /^(\d+)\.(\d+)$/) {
        my ($major, $minor) = (int($1), int($2));
        # cannot support 16.10 or older, their systemd is not cgroupv2 ready
        die "unsupported ancient Ubuntu version '$version'\n" if $major < 17;

        log_warn("The container's Ubuntu version '$version' is not in the known version list."
            . " As it's newer than the minimum supported version it's likely to work OK, but full"
            . " compatibility cannot be guaranteed. Please check for PVE system updates.\n");
    } else {
        die "unsupported and unexpected Ubuntu version '$version'\n";
    }

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "ubuntu";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;

    my $version = $self->{version};

    if ($version >= '17.10' && $version < '23.04') {
        # enable systemd-networkd
        $self->ct_mkdir('/etc/systemd/system/multi-user.target.wants');
        $self->ct_mkdir('/etc/systemd/system/socket.target.wants');
        $self->ct_symlink(
            '/lib/systemd/system/systemd-networkd.service',
            '/etc/systemd/system/multi-user.target.wants/systemd-networkd.service',
        );
        $self->ct_symlink(
            '/lib/systemd/system/systemd-networkd.socket',
            '/etc/systemd/system/socket.target.wants/systemd-networkd.socket',
        );
    }

    if ($version >= '17.10') {
        # unlink default netplan lxc config
        $self->ct_unlink('/etc/netplan/10-lxc.yaml');
    }

    if ($version eq '15.04' || $version eq '15.10' || $version eq '16.04') {
        # edit /etc/securetty (enable login on console)
        $self->setup_securetty($conf, qw(pts/0));
    }

    if ($version eq '12.04') {
        # suppress log level output for udev
        my $filename = '/etc/udev/udev.conf';
        my $data = $self->ct_file_get_contents($filename);
        $data =~ s/=\"err\"/=0/m;
        $self->ct_file_set_contents($filename, $data);
    }
}

sub setup_init {
    my ($self, $conf) = @_;

    my $version = $self->{version};

    if ($version >= '23.04') {
        $self->setup_systemd_preset({ 'systemd-networkd.service' => 1 });
    }

    if ($version >= '16.10') {
        $self->setup_container_getty_service($conf);
    }

    if ($version eq '12.04' || $version eq '14.04') {
        my $ttycount = PVE::LXC::Config->get_tty_count($conf);
        for (my $i = 1; $i < 7; $i++) {
            my $filename = "/etc/init/tty$i.conf";
            if ($i <= $ttycount) {
                my $tty_conf = <<__EOD__;
# tty$i - getty
#
# This service maintains a getty on tty$i from the point the system is
# started until it is shut down again.

start on stopped rc RUNLEVEL=[2345] and (
            not-container or
            container CONTAINER=lxc or
            container CONTAINER=lxc-libvirt)

stop on runlevel [!2345]

respawn
exec /sbin/getty -8 38400 tty$i
__EOD__
                $self->ct_file_set_contents($filename, $tty_conf);
            } else {
                for (my $i = $ttycount + 1; $i < 7; $i++) {
                    $self->ct_unlink($filename);
                }
            }
        }
    }
}

sub setup_network {
    my ($self, $conf) = @_;

    if ($self->{version} >= '17.10') {
        $self->setup_systemd_networkd($conf);
    } else {
        $self->SUPER::setup_network($conf);
    }
}

1;
