package PVE::LXC::Setup::Plugin;

# The abstract Plugin interface which user should restrict themself too.
#
# There are two main implementations of this interface:
# - Base: This is the base for all "normal" Linux system distros, where PVE tries to manage all
#   basic environment aspects (like network related configs, hostname). If something fails there,
#   the error should be relayed to the caller.
# - Unmanaged: this avoids doing as much as possible, assuming that the CT and it's enviroment gets
#   managed through other means (from manually or some other init or configuration stack). Due to
#   that, we should try to avoid erroring out but rather returning safe defaults or undef where we
#   cannot determine something. The calling code then needs to be able to handle this explicitly,
#   sometimes by having a dedicated check for the CT being of type "unmanaged".

use strict;
use warnings;

use Carp;

sub new {
    my ($class, $conf, $rootdir, $os_release, $log_warn) = @_;
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

sub check_systemd_nesting {
    my ($self, $conf, $init) = @_;
    croak "implement me in sub-class\n";
}

sub ssh_host_key_types_to_generate {
    my ($self) = @_;
    croak "implement me in sub-class\n";
}

sub detect_architecture {
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

sub post_restore_hook {
    my ($self, $conf, $root_password, $ssh_keys) = @_;
    croak "implement me in sub-class";
}

1;
