package PVE::LXC::Setup::Devuan;

use strict;
use warnings;

use PVE::Tools qw($IPV6RE);

use PVE::LXC::Setup::Debian;
use base qw(PVE::LXC::Setup::Debian);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $version = PVE::Tools::file_read_firstline("$rootdir/etc/devuan_version");

    die "unable to read version info\n" if !defined($version);

    die "unsupported Devuan version '$version'\n"
	if $version !~ /jessie|ascii/;

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "devuan";

    return bless $self, $class;
}

# the rest gets handled by the Debian plugin, which is compatible with older
# non-systemd Debian versions for now.

1;
