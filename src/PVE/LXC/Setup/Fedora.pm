package PVE::LXC::Setup::Fedora;

use strict;
use warnings;

use PVE::LXC::Setup::CentOS;

use base qw(PVE::LXC::Setup::CentOS);

sub new {
    my ($class, $conf, $rootdir) = @_;

    my $release = PVE::Tools::file_read_firstline("$rootdir/etc/fedora-release");
    die "unable to read version info\n" if !defined($release);

    my $version;

    if ($release =~ m/release\s+(\d+(?:\.\d+)?)(\.\d+)?/) {
	if ($1 >= 22 && $1 < 23) {
	    $version = $1;
	}
    }

    die "unsupported fedora release '$release'\n" if !$version;

    my $self = { conf => $conf, rootdir => $rootdir, version => $version };

    $conf->{ostype} = "fedora";

    return bless $self, $class;
}

1;
