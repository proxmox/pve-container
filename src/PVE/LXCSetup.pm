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

    my $rootfs = $conf->{'lxc.rootfs'};
    die "unable to find root filesystem\n" if !$rootfs || $rootfs eq '/';
    
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

sub set_dns {
    my ($self) = @_;

    $self->{plugin}->set_dns($self->{conf});
}

sub setup_init {
    my ($self) = @_;

    $self->{plugin}->setup_init($self->{conf});
}

sub set_user_password {
    my ($self, $user, $pw) = @_;
    
    $self->{plugin}->set_user_password($self->{conf}, $user, $pw);
}

sub pre_start_hook {
    my ($self) = @_;

    $self->{plugin}->pre_start_hook($self->{conf});
}

sub post_create_hook {
    my ($self, $root_password) = @_;

    $self->{plugin}->post_create_hook($self->{conf}, $root_password);
}

1;
