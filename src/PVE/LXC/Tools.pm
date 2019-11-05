# Module for lxc related functionality used mostly by our hooks.

package PVE::LXC::Tools;

use PVE::SafeSyslog;

# LXC introduced an `lxc.hook.version` property which allows hooks to be executed in different
# manners. The old way passes a lot of stuff as command line parameter, the new way passes
# environment variables.
#
# This is supposed to be a common entry point for hooks, consuming the parameters passed by lxc and
# passing them on to a subroutine in a defined way.
sub lxc_hook($$&) {
    my ($expected_type, $expected_section, $code) = @_;

    my ($ct_name, $section, $type);
    my $namespaces = {};
    my $args;

    my $version = $ENV{LXC_HOOK_VERSION} // '0';
    if ($version eq '0') {
	# Old style hook:
	$ct_name = shift @ARGV;
	$section = shift @ARGV;
	$type = shift @ARGV;

	if (!defined($ct_name) || !defined($section) || !defined($type)) {
	    die "missing hook parameters, expected to be called by lxc as hook\n";
	}

	if ($ct_name !~ /^\d+$/ || $section ne $expected_section || $type ne $expected_type) {
	    return;
	}

	if ($type eq 'stop') {
	    foreach my $ns (@ARGV) {
		if ($ns =~ /^([^:]+):(.+)$/) {
		    $namespaces->{$1} = $2;
		} else {
		    die "unrecognized 'stop' hook parameter: $ns\n";
		}
	    }
	} elsif ($type eq 'clone') {
	    $args = [@ARGV];
	}
    } elsif ($version eq '1') {
	$ct_name = $ENV{LXC_NAME}
	    or die "missing LXC_NAME environment variable\n";
	$section = $ENV{LXC_HOOK_SECTION}
	    or die "missing LXC_HOOK_SECTION environment variable\n";
	$type = $ENV{LXC_HOOK_TYPE}
	    or die "missing LXC_HOOK_TYPE environment variable\n";

	if ($ct_name !~ /^\d+$/ || $section ne $expected_section || $type ne $expected_type) {
	    return;
	}

	foreach my $var (keys %$ENV) {
	    if ($var =~ /^LXC_([A-Z]+)_NS$/) {
		$namespaces->{lc($1)} = $ENV{$1};
	    }
	}
    } else {
	die "lxc.hook.version $version not supported!\n";
    }

    my $logid = $ENV{PVE_LOG_ID} || "pve-lxc-hook-$section-$type";
    initlog($logid);

    my $common_vars = {
	ROOTFS_MOUNT => ($ENV{LXC_ROOTFS_MOUNT} or die "missing LXC_ROOTFS_MOUNT env var\n"),
	ROOTFS_PATH => ($ENV{LXC_ROOTFS_PATH} or die "missing LXC_ROOTFS_PATH env var\n"),
	CONFIG_FILE => ($ENV{LXC_CONFIG_FILE} or die "missing LXC_CONFIG_FILE env var\n"),
    };
    if (defined(my $target = $ENV{LXC_TARGET})) {
	$common_vars->{TARGET} = $target;
    }

    $code->($ct_name, $common_vars, $namespaces, $args);
}

1;
