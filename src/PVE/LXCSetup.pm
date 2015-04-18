package PVE::LXCSetup;

use strict;
use warnings;

use PVE::LXCSetup::Debian;

my $plugins = {
    debian =>  'PVE::LXCSetup::Debian',
};

sub new {
    my ($class, $type, $conf) = @_;

    my $self = bless { conf => $conf };

    $self->{plugin} = $plugins->{$type} ||
	"no such OS type '$type'\n";

    return $self;
}

sub setup_network {


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
