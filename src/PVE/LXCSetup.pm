package PVE::LXCSetup;

use strict;
use warnings;

use PVE::LXCSetup::Debian;

my $plugins = {
    debian =>  'PVE::LXCSetup::Debian',
};

my $autodetect_type = sub {
    my ($conf) = @_;
    
    my $rootfs = $conf->{'lxc.rootfs'};
    if (-f "$rootfs/etc/debian_version") {

	return "debian";
    }
    die "unable to detect OS disribution\n";
};

sub new {
    my ($class, $conf, $type) = @_;

    my $self = bless { conf => $conf };

    if (!defined($type)) {
	# try to autodetect type
	$type = &$autodetect_type($conf);
    }
    
    $self->{plugin} = $plugins->{$type} ||
	"no such OS type '$type'\n";

    return $self;
}

sub setup_network {
    my ($self) = @_;

    $self->{plugin}->setup_network($self->{conf});
}

sub set_hostname {
    my ($self) = @_;

    $self->{plugin}->set_hostname($self->{conf});
}

sub set_user_passwort {

}

sub post_create {
    my ($self) = @_;

    $self->{plugin}->post_create($self->{conf});
}

1;
