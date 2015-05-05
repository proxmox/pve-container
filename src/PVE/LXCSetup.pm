package PVE::LXCSetup;

use strict;
use warnings;

use PVE::LXCSetup::Debian;
use PVE::LXCSetup::Redhat;

my $plugins = {
    debian =>  'PVE::LXCSetup::Debian',
    redhat =>  'PVE::LXCSetup::Redhat',
};

my $autodetect_type = sub {
    my ($rootdir) = @_;
    
    if (-f "$rootdir/etc/debian_version") {
	return "debian";
    } elsif (-f  "$rootdir/etc/redhat-release") {
	return "redhat";
    }
    die "unable to detect OS disribution\n";
};

sub new {
    my ($class, $conf, $rootdir, $type) = @_;

    die "no root directory\n" if !$rootdir || $rootdir eq '/';

    my $self = bless { conf => $conf, $rootdir => $rootdir};

    if (!defined($type)) {
	# try to autodetect type
	$type = &$autodetect_type($rootdir);
    }
    
    my $plugin_class = $plugins->{$type} ||
	"no such OS type '$type'\n";

    $self->{plugin} = $plugin_class->new($conf, $rootdir);
    
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
