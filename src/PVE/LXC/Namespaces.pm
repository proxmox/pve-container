package PVE::LXC::Namespaces;

use strict;
use warnings;

use Fcntl qw(O_WRONLY);
use Socket;

use PVE::Tools qw(CLONE_NEWNS CLONE_NEWUSER);

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

sub run_in_userns(&;$) {
    my ($code, $id_map) = @_;
    socketpair(my $sp, my $sc, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair: $!\n";
    my $child = sub {
        close($sp);
        PVE::Tools::unshare(CLONE_NEWUSER | CLONE_NEWNS) or die "unshare(NEWUSER|NEWNS): $!\n";
        syswrite($sc, "1\n") == 2 or die "write: $!\n";
        shutdown($sc, 1);
        my $two = <$sc>;
        die "failed to sync with parent process\n" if $two ne "2\n";
        close($sc);
        $! = undef;
        ($(, $)) = (0, 0);
        die "$!\n" if $!;
        ($<, $>) = (0, 0);
        die "$!\n" if $!;
        return $code->();
    };
    my $parent = sub {
        my ($pid) = @_;
        close($sc);
        my $one = <$sp>;
        die "failed to sync with userprocess\n" if $one ne "1\n";
        set_id_map($pid, $id_map);
        syswrite($sp, "2\n") == 2 or die "write: $!\n";
        close($sp);
    };
    PVE::Tools::run_fork($child, { afterfork => $parent });
}

1;
