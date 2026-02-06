package PVE::LXC::Setup::Unmanaged;

use strict;
use warnings;

use PVE::LXC::Setup::Plugin;
use base qw(PVE::LXC::Setup::Plugin);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $self = { conf => $conf, rootdir => $rootdir };

    $conf->{ostype} = "unmanaged";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
}

sub setup_network {
    my ($self, $conf) = @_;
}

sub set_hostname {
    my ($self, $conf) = @_;
}

sub set_dns {
    my ($self, $conf) = @_;
}

sub set_timezone {
    my ($self, $conf) = @_;
}

sub setup_init {
    my ($self, $conf) = @_;
}

sub set_user_password {
    my ($self, $conf, $user, $opt_password) = @_;
}

sub unified_cgroupv2_support {
    my ($self, $init) = @_;
    return 1; # faking it won't normally hurt ;-)
}

sub get_ct_init_path {
    my ($self) = @_;
    # only passed to check_systemd_nesting and unified_cgroupv2_support for now
    return '/sbin/init';
}

sub check_systemd_nesting {
    my ($self, $conf, $init) = @_;
    return;
}

sub ssh_host_key_types_to_generate {
    my ($self) = @_;
    return;
}

sub detect_architecture {
    my ($self) = @_;
    return;
}

# hooks

sub pre_start_hook {
    my ($self, $conf) = @_;
}

sub post_clone_hook {
    my ($self, $conf) = @_;
}

sub post_create_hook {
    my ($self, $conf, $root_password, $ssh_keys) = @_;
}

1;
