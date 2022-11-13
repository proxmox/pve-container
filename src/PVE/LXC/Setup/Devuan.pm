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
    $version = lc($version);

    # map to Debian version, we sometimes check that
    my $version_map = {
	'jessie' => 8, # Devuan 1.0
	'ascii' => 9, # Devuan 2.0
	'ascii/ceres' => 9,
	'beowulf' => 10, # Devuan 3.0
	'beowulf/ceres' => 10,
	'chimaera' => 11, # Devuan 4.0
	'chimaera/ceres' => 11,
	'daedalus' => 12,
	'daedalus/ceres' => 12,
    };
    die "unsupported Devuan version '$version'\n" if !exists($version_map->{$version});

    my $self = {
	conf => $conf,
	rootdir => $rootdir,
	version => $version_map->{$version},
	devuan_version => $version,
    };

    $conf->{ostype} = "devuan";

    return bless $self, $class;
}

# non systemd based containers work with pure cgroupv2
sub unified_cgroupv2_support {
    my ($self, $init) = @_;

    return 1;
}

# the rest gets handled by the Debian plugin, which is compatible with older
# non-systemd Debian versions for now.

1;
