package PVE::LXC::Namespaces;

use strict;
use warnings;

use Fcntl qw(O_WRONLY O_RDONLY);
use Socket;

use PVE::Tools qw(CLONE_NEWNS CLONE_NEWUSER O_CLOEXEC);

my sub set_id_map($$) {
    my ($pid, $id_map) = @_;

    my @gid_args = ();
    my @uid_args = ();

    for my $map ($id_map->@*) {
        my ($type, $ct, $host, $length) = $map->@*;

        push @gid_args, $ct, $host, $length if $type eq 'g';
        push @uid_args, $ct, $host, $length if $type eq 'u';
    }

    PVE::Tools::run_command(['newgidmap', $pid, @gid_args]) if scalar(@gid_args);
    PVE::Tools::run_command(['newuidmap', $pid, @uid_args]) if scalar(@uid_args);
}

my sub sync_send {
    my ($fh, $msg) = @_;

    syswrite($fh, $msg) == length($msg) or die "sync write of message \"$msg\" failed: $!\n";
}

my sub sync_recv {
    my ($fh, $expect) = @_;

    my $received = <$fh>;
    die "sync read failed (expected message \"$expect\")\n" if $received ne $expect;
}

sub run_in_userns($;$) {
    my ($code, $id_map) = @_;
    socketpair(my $sp, my $sc, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair: $!\n";
    my $child = sub {
        close($sp);
        PVE::Tools::unshare(CLONE_NEWUSER | CLONE_NEWNS) or die "unshare(NEWUSER|NEWNS): $!\n";
        sync_send($sc, "1\n");
        shutdown($sc, 1);
        sync_recv($sc, "2\n");
        close($sc);
        $! = undef;
        ($(, $)) = (0, 0);
        die "setgid(0): $!\n" if $!;
        ($<, $>) = (0, 0);
        die "setuid(0): $!\n" if $!;
        return $code->();
    };
    my $parent = sub {
        my ($pid) = @_;
        close($sc);
        sync_recv($sp, "1\n");
        set_id_map($pid, $id_map);
        sync_send($sp, "2\n");
        close($sp);
    };
    PVE::Tools::run_fork($child, { afterfork => $parent });
}

# Create a new user namespace with the provided idmap applied.
# Returns a file handle to the namespace.
sub new_userns($) {
    my ($id_map) = @_;
    socketpair(my $sp, my $sc, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair: $!\n";
    my $userns_fh;
    my $child = sub {
        close($sp);
        PVE::Tools::unshare(CLONE_NEWUSER) or die "unshare(NEWUSER): $!\n";
        sync_send($sc, "1\n");
        shutdown($sc, 1);
        sync_recv($sc, "2\n");
        close($sc);
    };
    my $parent = sub {
        my ($pid) = @_;
        close($sc);
        sync_recv($sp, "1\n");
        set_id_map($pid, $id_map);
        sysopen($userns_fh, "/proc/$pid/ns/user", O_RDONLY | O_CLOEXEC)
            or die "Failed to open user namespace of child: $!\n";
        sync_send($sp, "2\n");
        close($sp);
    };
    PVE::Tools::run_fork($child, { afterfork => $parent });

    return $userns_fh;
}

1;
