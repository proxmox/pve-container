# LXC monitor socket

package PVE::LXC::Monitor;

use strict;
use warnings;

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);
use POSIX qw(NAME_MAX);

use constant {
    STATE_STOPPED => 0,
    STATE_STARTING => 1,
    STATE_RUNNING => 2,
    STATE_STOPPING => 3,
    STATE_ABORTING => 4,
    STATE_FREEZING => 5,
    STATE_FROZEN => 6,
    STATE_THAWED => 7,
    MAX_STATE => 8,
};

my $LXC_MSG_SIZE = length(pack('I! Z' . (NAME_MAX + 1) . ' x![I] I', 0, "", 0));
# Unpack an lxc_msg struct.
my sub _unpack_lxc_msg($) {
    my ($packet) = @_;

    # struct lxc_msg {
    #     lxc_msg_type_t type;
    #     char name[NAME_MAX+1];
    #     int value;
    # };

    my ($type, $name, $value) = unpack('I!Z' . (NAME_MAX + 1) . 'I!', $packet);

    if ($type == 0) {
        $type = 'STATE';
    } elsif ($type == 1) {
        $type = 'PRIORITY';
    } elsif ($type == 2) {
        $type = 'EXITCODE';
    } else {
        warn "unsupported lxc message type $type received\n";
        $type = undef;
    }

    return ($type, $name, $value);
}

# Opens the monitor socket
#
# Dies on errors
sub get_monitor_socket {
    my $socket = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        # assumes that lxcpath is '/var/lib/lxc', the hex part is a hash of the lxcpath
        Peer => "\0lxc/ad055575fe28ddd5//var/lib/lxc",
    );
    if (!defined($socket)) {
        die "failed to connect to monitor socket: $!\n";
    }

    return $socket;
}

# Read an lxc message from a socket.
#
# Returns undef on EOF
# Otherwise returns a (type, vmid, value) tuple.
#
# The returned 'type' currently can be 'STATE', 'PRIORITY' or 'EXITSTATUS'.
sub read_lxc_message($) {
    my ($socket) = @_;

    my $msg;
    my $got = recv($socket, $msg, $LXC_MSG_SIZE, 0) // die "failed to read from state socket: $!\n";

    if (length($msg) == 0) {
        return undef;
    }

    die "short read on state socket ($LXC_MSG_SIZE != " . length($msg) . ")\n"
        if length($msg) != $LXC_MSG_SIZE;

    my ($type, $name, $value) = _unpack_lxc_msg($msg);

    return ($type, $name, $value);
}

1;
