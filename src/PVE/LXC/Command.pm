# LXC command socket client.
#
# For now this is only used to fetch the cgroup paths.
# This can also be extended to replace a few more `lxc-*` CLI invocations.
# (such as lxc-stop, info, freeze, unfreeze, or getting the init pid)

package PVE::LXC::Command;

use strict;
use warnings;

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM SOL_SOCKET SO_PASSCRED);

use base 'Exporter';

use constant {
    LXC_CMD_GET_CGROUP => 6,
    LXC_CMD_GET_LIMITING_CGROUP => 19,
};

our @EXPORT_OK = qw(
    raw_command_transaction
    simple_command
    get_cgroup_path
);

# Get the command socket for a container.
my sub _get_command_socket($) {
    my ($vmid) = @_;

    my $sock = IO::Socket::UNIX->new(
	Type => SOCK_STREAM(),
	Peer => "\0/var/lib/lxc/$vmid/command",
    );
    if (!defined($sock)) {
	return undef if $!{ECONNREFUSED};
	die "failed to connect to command socket: $!\n";
    }

    # The documentation for this talks more about the receiving end, and it
    # also *mostly works without, but then the kernel *sometimes* fails to
    # provide correct credentials.
    setsockopt($sock, SOL_SOCKET, SO_PASSCRED, 1)
        or die "failed to pass credentials to command socket: $!\n";

    return $sock;
}

# Create an lxc_cmd_req struct.
my sub _lxc_cmd_req($$) {
    my ($cmd, $datalen) = @_;

    # struct lxc_cmd_req {
    #     lxc_cmd_t cmd;
    #     int datalen;
    #     const void *data;
    # };
    #
    # Obviously the pointer makes no sense in the payload so we just use NULL.
    my $packet = pack('i!i!L!', $cmd, $datalen, 0);

    return $packet;
}

# Unpack an lxc_cmd_rsp into result into its result and payload length.
my sub _unpack_lxc_cmd_rsp($) {
    my ($packet) = @_;

    #struct lxc_cmd_rsp {
    #    int ret; /* 0 on success, -errno on failure */
    #    int datalen;
    #    void *data;
    #};

    # We drop the pointless pointer value.
    my ($ret, $len, undef) = unpack("i!i!L!", $packet);

    return ($ret, $len);
}

# Send a complete packet:
my sub _do_send($$) {
    my ($sock, $data) = @_;
    my $sent = send($sock, $data, 0)
	// die "failed to send to command socket: $!\n";
    die "short write on command socket ($sent != ".length($data).")\n"
	if $sent != length($data);
}

# Send a complete packet:
my sub _do_recv($\$$) {
    my ($sock, $scalar, $len) = @_;
    my $got = recv($sock, $$scalar, $len, 0)
	// die "failed to read from command socket: $!\n";
    die "short read on command socket ($len != ".length($$scalar).")\n"
	if length($$scalar) != $len;
}

# Receive a response from an lxc command socket.
#
# Performs the return value check (negative errno values) and returns the
# return value and payload in array context, or just the payload in scalar
# context.
my sub _recv_response($) {
    my ($socket) = @_;

    my $buf = pack('i!i!L!', 0, 0, 0); # struct lxc_cmd_rsp
    _do_recv($socket, $buf, length($buf));

    my ($res, $datalen) = _unpack_lxc_cmd_rsp($buf);
    my $data;
    _do_recv($socket, $data, $datalen)
	if $datalen > 0;

    if ($res < 0) {
	$! = -$res;
	die "command failed: $!\n";
    }

    return wantarray ? ($res, $data) : $data;
}

# Perform a command transaction: Send command & payload, receive and unpack the
# response.
sub raw_command_transaction($$;$) {
    my ($socket, $cmd, $data) = @_;

    $data //= '';

    my $req = _lxc_cmd_req(LXC_CMD_GET_CGROUP, length($data));
    _do_send($socket, $req);
    if (length($data) > 0) {
	_do_send($socket, $data);
    }

    return _recv_response($socket);
}

# Perform a command transaction for a VMID where no command socket has been
# established yet.
#
# Returns ($ret, $data):
#    $ret: numeric return value (typically 0)
#    $data: optional data returned for the command, if any, otherwise undef
#
# Returns undef if the container is not running, dies on errors.
sub simple_command($$;$) {
    my ($vmid, $cmd, $data) = @_;

    my $socket = _get_command_socket($vmid)
	or return undef;
    return raw_command_transaction($socket, $cmd, $data);
}

# Retrieve the cgroup path for a running container.
# If $limiting is set, get the payload path without the namespace subdirectory,
# otherwise return the full namespaced path.
#
# Returns undef if the container is not running, dies on errors.
sub get_cgroup_path($;$$) {
    my ($vmid, $subsystem, $limiting) = @_;

    # subsystem name must be a zero-terminated C string.
    my ($res, $data) = simple_command(
	$vmid,
	$limiting ? LXC_CMD_GET_LIMITING_CGROUP : LXC_CMD_GET_CGROUP,
	pack('Z*', $subsystem),
    );
    return undef if !defined $res;

    # data is a zero-terminated string:
    return unpack('Z*', $data);
}

# Retrieve the cgroup path for a running container.
# If $limiting is set, get the payload path without the namespace subdirectory,
# otherwise return the full namespaced path.
#
# Returns undef if the container is not running, dies on errors.
sub get_limiting_cgroup_path($;$) {
    my ($vmid, $subsystem) = @_;

    # subsystem name must be a zero-terminated C string.
    my ($res, $data) = simple_command(
	$vmid,
	LXC_CMD_GET_LIMITING_CGROUP,
	pack('Z*', $subsystem),
    );
    return undef if !defined $res;

    # data is a zero-terminated string:
    return unpack('Z*', $data);
}

1;
