#!/usr/bin/perl

use strict;
use warnings;

use Cwd;
use File::Path;

use lib qw(..);

use PVE::LXC;

my $pwd = getcwd();

my $rootdir = "./tmproot";
my $destdir = "/mnt";

my $sharedir = "/tmpshare";
my $a        = "/tmpshare/a";
my $ab       = "/tmpshare/a/b";
my $abc      = "/tmpshare/a/b/c";
my $sym      = "/tmpshare/sym";
my $tmp      = "/tmpshare/tmp";

my $secret = "/secret";

END { cleanup(); };
sub cleanup {
    my $ignore_error;
    File::Path::rmtree("$pwd/$rootdir", {error => \$ignore_error});
    File::Path::rmtree("$pwd/$sharedir", {error => \$ignore_error});
    File::Path::rmtree("$pwd/$secret", {error => \$ignore_error});
}

sub setup {
    # Create all the test paths...
    PVE::LXC::walk_tree_nofollow('.', $rootdir, 1);
    PVE::LXC::walk_tree_nofollow($rootdir, $destdir, 1);
    PVE::LXC::walk_tree_nofollow('.', $abc, 1);
    PVE::LXC::walk_tree_nofollow('.', $secret, 1);
    # Create one evil symlink
    symlink('a/b', "$pwd/$sym") or die "failed to prepare test folders: $!\n";
}

setup();

# Test walk_tree_nofollow:
eval { PVE::LXC::walk_tree_nofollow('.', $rootdir, 0) };
die "unexpected error: $@" if $@;
eval { PVE::LXC::walk_tree_nofollow('.', "$sym/c", 0) };
die "failed to catch symlink at $sym/c\n" if !$@;
die "unexpected test error: '$@'\n" if $@ ne "symlink encountered at: .$sym\n";

# Bindmount testing:
sub bindmount {
    my ($from, $rootdir, $destdir, $inject, $ro, $inject_write, $restore) = @_;

    my ($mpath, $mpfd, $parentfd, $last);
    ($rootdir, $mpath, $mpfd, $parentfd, $last) =
        PVE::LXC::__mount_prepare_rootdir($rootdir, $destdir);

    my $srcdh = PVE::LXC::__bindmount_prepare('.', $from);

    if ($inject) {
	if ($restore) {
	    rename(".$inject", ".$tmp")
		or die "failed to move directory: $!\n";
	} else {
	    File::Path::rmtree(".$inject");
	}
	symlink("$pwd/$secret", ".$inject")
	    or die "failed to create symlink\n";
	File::Path::mkpath(".$from");
    }
    eval {
	PVE::LXC::__bindmount_do(".$from", $mpath, $inject_write ? 0 : $ro);

	if ($restore) {
	    unlink(".$inject") or die "failed to restore path: $!\n";
	    rename(".$tmp", ".$inject") or die "failed to restore path: $!\n";
	}

	PVE::LXC::__bindmount_verify($srcdh, $parentfd, $last, $ro)
	    or die "bindmount verification failed\n";
    };
    my $err = $@;
    system('umount', $mpath);
    die $err if $err;
}

bindmount($a, $rootdir, $destdir, undef, 0, 0);
eval { bindmount($sym, $rootdir, $destdir, undef, 0, 0) };
die "illegal symlink bindmount went through\n" if !$@;
die "unexpected test error: $@\n" if $@ ne "symlink encountered at: .$sym\n";
bindmount($abc, $rootdir, $destdir, undef, 0, 0);
# Race test: Assume someone exchanged 2 equivalent bind mounts between and
# after the bindmount_do()'s mount and remount calls.
# First: non-ro mount, should pass
bindmount($abc, $rootdir, $destdir, undef, 0, 1);
# Second: regular read-only mount, should pass.
bindmount($abc, $rootdir, $destdir, undef, 1, 0);
# Third: read-only requested with read-write injected
eval { bindmount($abc, $rootdir, $destdir, undef, 1, 1) };
die "read-write mount possible\n" if !$@;
die "unexpected test error: $@\n" if $@ ne "failed to mark bind mount read only\n";
# Race test: Replace /tmpshare/a/b with a symlink to /secret just before
# __bindmount_do().
eval { bindmount($abc, $rootdir, $destdir, $ab, 0, 0) };
die "injected symlink bindmount went through\n" if !$@;
die "unexpected test error: $@\n" if $@ ne "bindmount verification failed\n";
# Restore setup:
cleanup();
setup();
# Race test 2: As above but also reset the symlink back after __bindmount_do()
eval { bindmount($abc, $rootdir, $destdir, $ab, 0, 0, 1) };
die "injected symlink bindmount went through\n" if !$@;
die "unexpected test error: $@\n" if $@ ne "bindmount verification failed\n";
