package PVE::LXC::Setup::NixOS;

use strict;
use warnings;

use File::Path 'make_path';

use PVE::LXC::Setup::Base;
use PVE::LXC::Tools;

use base qw(PVE::LXC::Setup::Base);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $self = { conf => $conf, rootdir => $rootdir, version => 0 };

    $conf->{ostype} = "nixos";

    return bless $self, $class;
}

sub template_fixup {
    my ($self, $conf) = @_;
}

sub setup_network {
    my ($self, $conf) = @_;

    $self->setup_systemd_networkd($conf);
}

sub set_timezone {
    my ($self, $conf) = @_;
}

sub setup_init {
    my ($self, $conf) = @_;
}

sub detect_architecture {
    my ($self) = @_;

    # /bin/sh only exists as a symlink after the initial system activaction on first boot.
    # To detect the actual architecture of the system, examine the shebang line of the /sbin/init
    # script, which has the full path to the system shell.
    my $init_path = '/sbin/init';
    open(my $fh, '<', $init_path) or die "open '$init_path' failed: $!\n";

    if (<$fh> =~ /^#! ?(\S*)/) {
        return PVE::LXC::Tools::detect_elf_architecture($1);
    }

    die "could not find a shell\n";
}

1;
