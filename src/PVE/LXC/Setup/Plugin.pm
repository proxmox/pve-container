package PVE::LXC::Setup::Plugin;

# the abstract Plugin interface which user should restrict themself too

use strict;
use warnings;

use Carp;

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;
    croak "implement me in sub-class\n";
}

sub template_fixup {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub setup_network {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub set_hostname {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub set_dns {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub set_timezone {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub setup_init {
    my ($self, $conf) = @_;
    croak "implement me in sub-class\n";
}

sub set_user_password {
    my ($self, $conf, $user, $opt_password) = @_;
    croak "implement me in sub-class\n";
}

sub unified_cgroupv2_support {
    my ($self, $init) = @_;
    croak "implement me in sub-class\n";
}

sub get_ct_init_path {
    my ($self) = @_;
    croak "implement me in sub-class\n";
}

sub ssh_host_key_types_to_generate {
    my ($self) = @_;
    croak "implement me in sub-class\n";
}

# hooks

sub pre_start_hook {
    my ($self, $conf) = @_;
    croak "implement me in sub-class";
}

sub post_clone_hook {
    my ($self, $conf) = @_;
    croak "implement me in sub-class";
}

sub post_create_hook {
    my ($self, $conf, $root_password, $ssh_keys) = @_;
    croak "implement me in sub-class";
}

1;
