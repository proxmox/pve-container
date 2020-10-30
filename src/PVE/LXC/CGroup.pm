# cgroup handler
#
# This package should deal with figuring out the right cgroup path for a
# container (via the command socket), reading and writing cgroup values, and
# handling cgroup v1 & v2 differences.
#
# Note that the long term plan is to have resource manage functions instead of
# dealing with cgroup files on the outside.

package PVE::LXC::CGroup;

use strict;
use warnings;

use PVE::LXC::Command;
use PVE::CGroup;
use base('PVE::CGroup');


# Get a subdirectory (without the cgroup mount point) for a controller.
#
# If `$controller` is `undef`, get the unified (cgroupv2) path.
#
# Note that in cgroup v2, lxc uses the activated controller names
# (`cgroup.controllers` file) as list of controllers for the unified hierarchy,
# so this returns a result when a `controller` is provided even when using
# a pure cgroupv2 setup.
sub get_subdir {
    my ($self, $controller, $limiting) = @_;

    my $entry_name = $controller || 'unified';
    my $entry = ($self->{controllers}->{$entry_name} //= {});

    my $kind = $limiting ? 'limit' : 'ns';
    my $path = $entry->{$kind};

    return $path if defined $path;

    $path = PVE::LXC::Command::get_cgroup_path(
	$self->{vmid},
	$controller,
	$limiting,
    ) or return undef;

    # untaint:
    if ($path =~ /\.\./) {
	die "lxc returned suspicious path: '$path'\n";
    }
    ($path) = ($path =~ /^(.*)$/s);

    $entry->{$kind} = $path;

    return $path;
}

1;
