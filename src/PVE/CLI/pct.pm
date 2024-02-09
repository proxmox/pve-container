package PVE::CLI::pct;

use strict;
use warnings;

use Fcntl;
use File::Copy 'copy';
use POSIX;

use PVE::CLIHandler;
use PVE::Cluster;
use PVE::CpuSet;
use PVE::Exception qw(raise_param_exc);
use PVE::GuestHelpers;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::LXC::CGroup;
use PVE::RPCEnvironment;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);

use PVE::API2::LXC::Config;
use PVE::API2::LXC::Snapshot;
use PVE::API2::LXC::Status;
use PVE::API2::LXC;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit(PVE::Tools::upid_status_is_error($status) ? -1 : 0);
};

sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Show CT status.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    verbose => {
		description => "Verbose output format",
		type => 'boolean',
		optional => 1,
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	# test if CT exists
	my $conf = PVE::LXC::Config->load_config ($param->{vmid});

	my $vmstatus = PVE::LXC::vmstatus($param->{vmid});
	my $stat = $vmstatus->{$param->{vmid}};
	if ($param->{verbose}) {
	    foreach my $k (sort (keys %$stat)) {
		my $v = $stat->{$k};
		next if !defined($v);
		next if $k eq 'cpu';
		print "$k: $v\n";
	    }
	} else {
	    my $status = $stat->{status} || 'unknown';
	    print "status: $status\n";
	}

	return undef;
    }});

sub param_mapping {
    my ($name) = @_;

    my $mapping = {
	'create_vm' => [
	    PVE::CLIHandler::get_standard_mapping('pve-password'),
	    'ssh-public-keys',
	],
    };

    return $mapping->{$name};
}

__PACKAGE__->register_method ({
    name => 'unlock',
    path => 'unlock',
    method => 'PUT',
    description => "Unlock the VM.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	PVE::LXC::Config->remove_lock($vmid);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'console',
    path => 'console',
    method => 'GET',
    description => "Launch a console for the specified container.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	    escape => {
		description => "Escape sequence prefix. For example to use <Ctrl+b q> as the escape sequence pass '^b'.",
		default =>  '^a',
		type => 'string',
		pattern => '\^?[a-z]',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	# test if container exists on this node
	my $conf = PVE::LXC::Config->load_config($param->{vmid});

	my $cmd = PVE::LXC::get_console_command($param->{vmid}, $conf, $param->{escape});
	exec(@$cmd);
    }});

# TODO: Evaluate if still needed with PVE9
sub clean_environment {
    # These env variables are currently needed by PVE to work correctly with rust libraries,
    # but can break ssl inside of containers.
    # An explanation why they are needed and the code that sets them can be found here:
    # https://git.proxmox.com/?p=proxmox-perl-rs.git;a=blob;f=common/pkg/Proxmox/Lib/SslProbe.pm
    delete $ENV{SSL_CERT_FILE};
    delete $ENV{SSL_CERT_DIR};
};

__PACKAGE__->register_method ({
    name => 'enter',
    path => 'enter',
    method => 'GET',
    description => "Launch a shell for the specified container.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	    # FIXME: passing the environment into the container potentially leaks hosts secrets, or causes
	    # unexpected behavior. Change to opt-in for pve 9
	    'keep-env' => {
		type => 'boolean',
		description => "Keep the current environment. This option will disabled by default with PVE 9."
		    ." If you rely on a preserved environment, please use this option to be future-proof.",
		optional => 1,
		default => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;
	my $keep_env = $param->{'keep-env'} // 1; # FIXME: switch to default 0 with pve 9, see above

	my $vmid = $param->{vmid};

	PVE::LXC::Config->load_config($vmid); # test if container exists on this node
	die "container '$vmid' not running!\n" if !PVE::LXC::check_running($vmid);

	clean_environment();

	my @lxc_attach_cmd = ('lxc-attach', '-n', $vmid);
	push @lxc_attach_cmd, $keep_env ? '--keep-env' : '--clear-env';
	exec(@lxc_attach_cmd);
    }});

__PACKAGE__->register_method ({
    name => 'exec',
    path => 'exec',
    method => 'GET',
    description => "Launch a command inside the specified container.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	    'keep-env' => {
		type => 'boolean',
		description => "Keep the current environment. This option will disabled by default with PVE 9."
		    ." If you rely on a preserved environment, please use this option to be future-proof.",
		optional => 1,
		default => 1, # FIXME: switch to default 0 with pve 9, see enter method
	    },
	    'extra-args' => get_standard_option('extra-args'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $keep_env = $param->{'keep-env'} // 1; # FIXME: switch to default 0 with pve 9, see enter method

	my $vmid = $param->{vmid};
	PVE::LXC::Config->load_config($vmid); # test if container exists on this node
	die "container '$vmid' not running!\n" if !PVE::LXC::check_running($vmid);

	die "missing command" if !@{$param->{'extra-args'}};

	clean_environment();

	my @lxc_attach_cmd = ('lxc-attach', '-n', $vmid);
	push @lxc_attach_cmd, $keep_env ? '--keep-env' : '--clear-env';
	push @lxc_attach_cmd, '--', @{$param->{'extra-args'}};
	exec(@lxc_attach_cmd);
    }});

__PACKAGE__->register_method ({
    name => 'fsck',
    path => 'fsck',
    method => 'PUT',
    description => "Run a filesystem check (fsck) on a container volume.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_stopped }),
	    force => {
		optional => 1,
		type => 'boolean',
		description => "Force checking, even if the filesystem seems clean",
		default => 0,
	    },
	    device => {
		optional => 1,
		type => 'string',
		description => "A volume on which to run the filesystem check",
		enum => [PVE::LXC::Config->valid_volume_keys()],
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{'vmid'};
	my $device = defined($param->{'device'}) ? $param->{'device'} : 'rootfs';

	my $command = ['fsck', '-a', '-l'];
	push(@$command, '-f') if $param->{force};

	# critical path: all of this will be done while the container is locked
	my $do_fsck = sub {

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    my $storage_cfg = PVE::Storage::config();

	    defined($conf->{$device}) || die "cannot run command on non-existing mount point $device\n";

	    my $mount_point = PVE::LXC::Config->parse_volume($device, $conf->{$device});

	    die "cannot run fsck when container is running\n"
		if PVE::LXC::check_running($vmid);

	    my $volid = $mount_point->{volume};

	    my $path;
	    my $storage_id = PVE::Storage::parse_volume_id($volid, 1);

	    if ($storage_id) {
		my (undef, undef, undef, undef, undef, undef, $format) =
		    PVE::Storage::parse_volname($storage_cfg, $volid);

		die "unable to run fsck for '$volid' (format == $format)\n"
		    if $format ne 'raw';

		$path = PVE::Storage::map_volume($storage_cfg, $volid);

	    } else {
		if (($volid =~ m|^/.+|) && (-b $volid)) {
		    # pass block devices directly
		    $path = $volid;
		} else {
		    die "path '$volid' does not point to a block device\n";
		}
	    }

	    push(@$command, $path);
	    PVE::Tools::run_command($command);

	    PVE::Storage::unmap_volume($storage_cfg, $volid) if $storage_id;
	};

	PVE::LXC::Config->lock_config($vmid, $do_fsck);
	return undef;
    }});

__PACKAGE__->register_method({
    name => 'mount',
    path => 'mount',
    method => 'POST',
    description => "Mount the container's filesystem on the host. " .
		   "This will hold a lock on the container and is meant for emergency maintenance only " .
		   "as it will prevent further operations on the container other than start and stop.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $vmid = extract_param($param, 'vmid');
	my $storecfg = PVE::Storage::config();
	PVE::LXC::Config->lock_config($vmid, sub {
	    my $conf = PVE::LXC::Config->set_lock($vmid, 'mounted');
	    PVE::LXC::mount_all($vmid, $storecfg, $conf);
	});

	print "mounted CT $vmid in '/var/lib/lxc/$vmid/rootfs'\n";
	return undef;
    }});

__PACKAGE__->register_method({
    name => 'unmount',
    path => 'unmount',
    method => 'POST',
    description => "Unmount the container's filesystem.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $vmid = extract_param($param, 'vmid');
	my $storecfg = PVE::Storage::config();
	PVE::LXC::Config->lock_config($vmid, sub {
	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::umount_all($vmid, $storecfg, $conf, 0);
	    PVE::LXC::Config->remove_lock($vmid, 'mounted');
	});
	return undef;
    }});

__PACKAGE__->register_method({
    name => 'df',
    path => 'df',
    method => 'GET',
    description => "Get the container's current disk usage.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	# JSONSchema's format_size is exact, this uses floating point numbers
	my $format = sub {
	    my ($size) = @_;
	    return $size if $size < 1024.;
	    $size /= 1024.;
	    return sprintf('%.1fK', ${size}) if $size < 1024.;
	    $size /= 1024.;
	    return sprintf('%.1fM', ${size}) if $size < 1024.;
	    $size /= 1024.;
	    return sprintf('%.1fG', ${size}) if $size < 1024.;
	    $size /= 1024.;
	    return sprintf('%.1fT', ${size}) if $size < 1024.;
	};

	my $vmid = extract_param($param, 'vmid');
	PVE::LXC::Config->lock_config($vmid, sub {
	    my $pid = eval { PVE::LXC::find_lxc_pid($vmid) };
	    my ($conf, $rootdir, $storecfg, $mounted);
	    if ($@ || !$pid) {
		$conf = PVE::LXC::Config->set_lock($vmid, 'mounted');
		$rootdir = "/var/lib/lxc/$vmid/rootfs";
		$storecfg = PVE::Storage::config();
		PVE::LXC::mount_all($vmid, $storecfg, $conf);
		$mounted = 1;
	    } else {
		$conf = PVE::LXC::Config->load_config($vmid);
		$rootdir = "/proc/$pid/root";
	    }

	    my @list = [qw(MP Volume Size Used Avail Use% Path)];
	    my @len = map { length($_) } @{$list[0]};

	    eval {
		PVE::LXC::Config->foreach_volume($conf, sub {
		    my ($name, $mp) = @_;
		    my $path = $mp->{mp};

		    my $df = PVE::Tools::df("$rootdir/$path", 3);
		    my $total = $format->($df->{total});
		    my $used = $format->($df->{used});
		    my $avail = $format->($df->{avail});

		    my $pc = sprintf('%.1f', $df->{used}/$df->{total});

		    my $entry = [ $name, $mp->{volume}, $total, $used, $avail, $pc, $path ];
		    push @list, $entry;

		    foreach my $i (0..5) {
			$len[$i] = length($entry->[$i])
			    if $len[$i] < length($entry->[$i]);
		    }
		});

		my $format = "%-$len[0]s %-$len[1]s %$len[2]s %$len[3]s %$len[4]s %$len[5]s %s\n";
		printf($format, @$_) foreach @list;
	    };
	    warn $@ if $@;

	    if ($mounted) {
		PVE::LXC::umount_all($vmid, $storecfg, $conf, 0);
		PVE::LXC::Config->remove_lock($vmid, 'mounted');
	    }
	});
	return undef;
    }});

# File creation with specified ownership and permissions.
# User and group can be names or decimal numbers.
# Permissions are explicit (not affected by umask) and can be numeric with the
# usual 0/0x prefixes for octal/hex.
sub create_file {
    my ($path, $perms, $user, $group) = @_;
    my ($uid, $gid);
    if (defined($user)) {
	if ($user =~ /^\d+$/) {
	    $uid = int($user);
	} else {
	    $uid = getpwnam($user);
	    die "failed to get uid for: $user\n" if !defined($uid);
	}
    }
    if (defined($group)) {
	if ($group =~ /^\d+$/) {
	    $gid = int($group);
	} else {
	    $gid = getgrnam($group);
	    die "failed to get gid for: $group\n" if !defined($gid);
	}
    }

    if (defined($perms)) {
	$! = 0;
	my ($mode, $unparsed) = POSIX::strtoul($perms, 0);
	die "invalid mode: '$perms'\n" if $perms eq '' || $unparsed > 0 || $!;
	$perms = $mode;
    }

    my $fd;
    if (sysopen($fd, $path, O_WRONLY | O_CREAT | O_EXCL, 0)) {
	$perms = 0666 & ~umask if !defined($perms);
    } else {
	# If the path previously existed then we do not care about left-over
	# file descriptors even if the permissions/ownership is changed.
	sysopen($fd, $path, O_WRONLY | O_CREAT | O_TRUNC)
	    or die "failed to create file: $path: $!\n";
    }

    my $trunc = 0;

    if (defined($perms)) {
	$trunc = 1;
	chmod($perms, $fd);
    }

    if (defined($uid) || defined($gid)) {
	$trunc = 1;
	if (!defined($uid) || !defined($gid)) {
	    my ($fuid, $fgid) = (stat($fd))[4,5];
	    $uid //= $fuid;
	    $gid //= $fgid;
	}
	chown($uid, $gid, $fd) or die "failed to change file owner: $!\n";
    }
    return $fd;
}

__PACKAGE__->register_method ({
    name => 'rescan',
    path => 'rescan',
    method => 'POST',
    description => "Rescan all storages and update disk sizes and unused disk images.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', {
		optional => 1,
		completion => \&PVE::LXC::complete_ctid,
	    }),
	    dryrun => {
		type => 'boolean',
		optional => 1,
		default => 0,
		description => 'Do not actually write changes out to conifg.',
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $dryrun = $param->{dryrun};

	print "NOTE: running in dry-run mode, won't write changes out!\n" if $dryrun;

	PVE::LXC::rescan($param->{vmid}, 0, $dryrun);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'pull',
    path => 'pull',
    method => 'PUT',
    description => "Copy a file from the container to the local system.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    path => {
		type => 'string',
		description => "Path to a file inside the container to pull.",
	    },
	    destination => {
		type => 'string',
		description => "Destination",
	    },
	    user => {
		type => 'string',
		description => 'Owner user name or id.',
		optional => 1,
	    },
	    group => {
		type => 'string',
		description => 'Owner group name or id.',
		optional => 1,
	    },
	    perms => {
		type => 'string',
		description => "File permissions to use (octal by default, prefix with '0x' for hexadecimal).",
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $vmid = extract_param($param, 'vmid');
	my $path = extract_param($param, 'path');
	my $dest = extract_param($param, 'destination');

	my $perms = extract_param($param, 'perms');
	# assume octal as default
	$perms = "0$perms" if defined($perms) && $perms !~m/^0/;
	my $user = extract_param($param, 'user');
	my $group = extract_param($param, 'group');

	my $code = sub {
	    my $running = PVE::LXC::check_running($vmid);
	    die "can only pull files from a running VM" if !$running;

	    my $realcmd = sub {
		my $pid = PVE::LXC::find_lxc_pid($vmid);
		# Avoid symlink issues by opening the files from inside the
		# corresponding namespaces.
		my $destfd = create_file($dest, $perms, $user, $group);

		sysopen my $mntnsfd, "/proc/$pid/ns/mnt", O_RDONLY
		    or die "failed to open the container's mount namespace\n";
		PVE::Tools::setns(fileno($mntnsfd), PVE::Tools::CLONE_NEWNS)
		    or die "failed to enter the container's mount namespace\n";
		close($mntnsfd);
		chdir('/') or die "failed to change to container root directory\n";

		open my $srcfd, '<', $path
		    or die "failed to open $path: $!\n";

		copy($srcfd, $destfd);
	    };

	    # This avoids having to setns() back to our namespace.
	    return $rpcenv->fork_worker('pull_file', $vmid, undef, $realcmd);
	};

	return PVE::LXC::Config->lock_config($vmid, $code);
    }});

__PACKAGE__->register_method({
    name => 'push',
    path => 'push',
    method => 'PUT',
    description => "Copy a local file to the container.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    file => {
		type => 'string',
		description => "Path to a local file.",
	    },
	    destination => {
		type => 'string',
		description => "Destination inside the container to write to.",
	    },
	    user => {
		type => 'string',
		description => 'Owner user name or id. When using a name it must exist inside the container.',
		optional => 1,
	    },
	    group => {
		type => 'string',
		description => 'Owner group name or id. When using a name it must exist inside the container.',
		optional => 1,
	    },
	    perms => {
		type => 'string',
		description => "File permissions to use (octal by default, prefix with '0x' for hexadecimal).",
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $vmid = extract_param($param, 'vmid');
	my $file = extract_param($param, 'file');
	my $dest = extract_param($param, 'destination');

	my $perms = extract_param($param, 'perms');
	# assume octal as default
	$perms = "0$perms" if defined($perms) && $perms !~m/^0/;
	my $user = extract_param($param, 'user');
	my $group = extract_param($param, 'group');

	my $code = sub {
	    my $running = PVE::LXC::check_running($vmid);
	    die "can only push files to a running CT\n" if !$running;

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    my $unprivileged = $conf->{unprivileged};

	    my $realcmd = sub {
		my $pid = PVE::LXC::find_lxc_pid($vmid);
		# We open the file then enter the container's mount - and for
		# unprivileged containers - user namespace and then create the
		# file. This avoids symlink attacks as a symlink cannot point
		# outside the namespace and our own access is equivalent to the
		# container-local's root user. Also the user-passed -user and
		# -group parameters will use the container-local's user and
		# group names.
		sysopen my $srcfd, $file, O_RDONLY
		    or die "failed to open $file for reading\n";

		sysopen my $mntnsfd, "/proc/$pid/ns/mnt", O_RDONLY
		    or die "failed to open the container's mount namespace\n";
		my $usernsfd;
		if ($unprivileged) {
		    sysopen $usernsfd, "/proc/$pid/ns/user", O_RDONLY
			or die "failed to open the container's user namespace\n";
		}

		PVE::Tools::setns(fileno($mntnsfd), PVE::Tools::CLONE_NEWNS)
		    or die "failed to enter the container's mount namespace\n";
		close($mntnsfd);
		chdir('/') or die "failed to change to container root directory\n";

		if ($unprivileged) {
		    PVE::Tools::setns(fileno($usernsfd), PVE::Tools::CLONE_NEWUSER)
			or die "failed to enter the container's user namespace\n";
		    close($usernsfd);
		    POSIX::setgid(0) or die "setgid failed: $!\n";
		    POSIX::setuid(0) or die "setuid failed: $!\n";
		}

		my $destfd = create_file($dest, $perms, $user, $group);
		copy($srcfd, $destfd);
	    };

	    # This avoids having to setns() back to our namespace.
	    return $rpcenv->fork_worker('push_file', $vmid, undef, $realcmd);
	};

	return PVE::LXC::Config->lock_config($vmid, $code);
    }});

__PACKAGE__->register_method ({
    name => 'cpusets',
    path => 'cpusets',
    method => 'GET',
    description => "Print the list of assigned CPU sets.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $ctlist = PVE::LXC::config_list();

	my $len = 0;
	my $id_len = 0;
	my $res = {};

	foreach my $vmid (sort keys %$ctlist) {
	    my $cgroup = PVE::LXC::CGroup->new($vmid);

	    my ($cpuset, $path);
	    if (defined($path = $cgroup->get_path('cpuset', 1))) {
		$cpuset = eval { PVE::CpuSet->new_from_path($path, 1); };
	    } elsif (defined($path = $cgroup->get_path(undef, 1))) {
		$cpuset = eval { PVE::CpuSet->new_from_path($path, 1); };
	    } else {
		# Container not running.
		next;
	    }
	    if (my $err = $@) {
		warn $err;
		next;
	    }

	    my @cpuset_members = $cpuset->members();

	    my $line = ': ';

	    my $last = $cpuset_members[-1];

	    for (my $id = 0; $id <= $last; $id++) {
		my $empty = ' ' x length("$id");
		$line .= ' ' . ($cpuset->has($id) ? $id : $empty);
	    }
	    $len = length($line) if length($line) > $len;
	    $id_len = length($vmid) if length($vmid) > $id_len;

	    $res->{$vmid} = $line;
	}

	my @vmlist = sort keys %$res;

	if (scalar(@vmlist)) {
	    my $header = '-' x ($len + $id_len) . "\n";

	    print $header;
	    foreach my $vmid (@vmlist) {
		print sprintf("%${id_len}i%s\n", $vmid, $res->{$vmid});
	    }
	    print $header;

	} else {
	    print "no running containers\n";
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'fstrim',
    path => 'fstrim',
    method => 'POST',
    description => "Run fstrim on a chosen CT and its mountpoints, except bind or read-only mountpoints.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    'ignore-mountpoints' => {
		description => 'Skip all mountpoints, only do fstrim on the container root.',
		optional => 1,
		type => 'boolean',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {

	my ($param) = @_;
	my $vmid = $param->{'vmid'};

	my $rootdir = "/var/lib/lxc/$vmid/rootfs";

	my $storecfg = PVE::Storage::config();
	my $conf = PVE::LXC::Config->set_lock($vmid, 'fstrim');
	eval {
	    my $path = "";
	    PVE::LXC::mount_all($vmid, $storecfg, $conf);
	    PVE::LXC::Config->foreach_volume($conf, sub {
		my ($name, $mp) = @_;
		$path = $mp->{mp};
		return if $mp->{type} eq 'bind' || $mp->{ro};
		return if $param->{'ignore-mountpoints'} && $name =~ /^mp\d+/;
		my $cmd = ["fstrim", "-v", "$rootdir$path"];
		PVE::Tools::run_command($cmd, noerr => 1);
	    });
	};
	warn $@ if $@;

	PVE::LXC::umount_all($vmid, $storecfg, $conf, 0);
	PVE::LXC::Config->remove_lock($vmid, 'fstrim');

	return undef;
    }});


__PACKAGE__->register_method({
    name => 'remote_migrate_vm',
    path => 'remote_migrate_vm',
    method => 'POST',
    description => "Migrate container to a remote cluster. Creates a new migration task. EXPERIMENTAL feature!",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Migrate' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    'target-vmid' => get_standard_option('pve-vmid', { optional => 1 }),
	    'target-endpoint' => get_standard_option('proxmox-remote', {
		description => "Remote target endpoint",
	    }),
	    online => {
		type => 'boolean',
		description => "Use online/live migration.",
		optional => 1,
	    },
	    restart => {
		type => 'boolean',
		description => "Use restart migration",
		optional => 1,
	    },
	    timeout => {
		type => 'integer',
		description => "Timeout in seconds for shutdown for restart migration",
		optional => 1,
		default => 180,
	    },
	    delete => {
		type => 'boolean',
		description => "Delete the original CT and related data after successful migration. By default the original CT is kept on the source cluster in a stopped state.",
		optional => 1,
		default => 0,
	    },
	    'target-storage' => get_standard_option('pve-targetstorage', {
		completion => \&PVE::QemuServer::complete_migration_storage,
		optional => 0,
	    }),
	    'target-bridge' => {
		type => 'string',
		description => "Mapping from source to target bridges. Providing only a single bridge ID maps all source bridges to that bridge. Providing the special value '1' will map each source bridge to itself.",
		format => 'bridge-pair-list',
	    },
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'integer',
		minimum => '0',
		default => 'migrate limit from datacenter or storage config',
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $source_vmid = $param->{vmid};
	my $target_endpoint = $param->{'target-endpoint'};
	my $target_vmid = $param->{'target-vmid'} // $source_vmid;

	my $remote = PVE::JSONSchema::parse_property_string('proxmox-remote', $target_endpoint);

	# TODO: move this as helper somewhere appropriate?
	my $conn_args = {
	    protocol => 'https',
	    host => $remote->{host},
	    port => $remote->{port} // 8006,
	    apitoken => $remote->{apitoken},
	};

	$conn_args->{cached_fingerprints} = { uc($remote->{fingerprint}) => 1 }
	    if defined($remote->{fingerprint});

	my $api_client = PVE::APIClient::LWP->new(%$conn_args);
	my $resources = $api_client->get("/cluster/resources", { type => 'vm' });
	if (grep { defined($_->{vmid}) && $_->{vmid} eq $target_vmid } @$resources) {
	    raise_param_exc({ target_vmid => "Guest with ID '$target_vmid' already exists on remote cluster" });
	}

	my $storages = $api_client->get("/nodes/localhost/storage", { enabled => 1 });

	my $storecfg = PVE::Storage::config();
	my $target_storage = $param->{'target-storage'};
	my $storagemap = eval { PVE::JSONSchema::parse_idmap($target_storage, 'pve-storage-id') };
	raise_param_exc({ 'target-storage' => "failed to parse storage map: $@" })
	    if $@;

	my $check_remote_storage = sub {
	    my ($storage) = @_;
	    my $found = [ grep { $_->{storage} eq $storage } @$storages ];
	    die "remote: storage '$storage' does not exist!\n"
		if !@$found;

	    $found = @$found[0];

	    my $content_types = [ PVE::Tools::split_list($found->{content}) ];
	    die "remote: storage '$storage' cannot store CT rootdir\n"
		if !grep { $_ eq 'rootdir' } @$content_types;
	};

	foreach my $target_sid (values %{$storagemap->{entries}}) {
	    $check_remote_storage->($target_sid);
	}

	$check_remote_storage->($storagemap->{default})
	    if $storagemap->{default};

	return PVE::API2::LXC->remote_migrate_vm($param);
    }});

our $cmddef = {
    list=> [ 'PVE::API2::LXC', 'vmlist', [], { node => $nodename }, sub {
	my $res = shift;
	return if !scalar(@$res);
	my $format = "%-10s %-10s %-12s %-20s\n";
	printf($format, 'VMID', 'Status', 'Lock', 'Name');
	foreach my $d (sort {$a->{vmid} <=> $b->{vmid} } @$res) {
	    my $lock = $d->{lock} || '';
	    printf($format, $d->{vmid}, $d->{status}, $lock, $d->{name});
	}
    }],
    config => [ "PVE::API2::LXC::Config", 'vm_config', ['vmid'], { node => $nodename }, sub {
	my $config = shift;
	for my $k (sort (keys %$config)) {
	    next if $k eq 'digest' || $k eq 'lxc';
	    my $v = $config->{$k};
	    if ($k eq 'description') {
		$v = PVE::Tools::encode_text($v);
	    }
	    print "$k: $v\n";
	}
	if (defined(my $lxc_list = $config->{'lxc'})) {
	    for my $lxc_opt (@$lxc_list) {
		print "$lxc_opt->[0]: $lxc_opt->[1]\n"
	    }
	}
    }],

    pending => [ "PVE::API2::LXC", "vm_pending", ['vmid'], { node => $nodename }, \&PVE::GuestHelpers::format_pending ],
    set => [ 'PVE::API2::LXC::Config', 'update_vm', ['vmid'], { node => $nodename }],

    resize => [ "PVE::API2::LXC", 'resize_vm', ['vmid', 'disk', 'size'], { node => $nodename } ],

    create => [ 'PVE::API2::LXC', 'create_vm', ['vmid', 'ostemplate'], { node => $nodename }, $upid_exit ],
    restore => [ 'PVE::API2::LXC', 'create_vm', ['vmid', 'ostemplate'], { node => $nodename, restore => 1 }, $upid_exit ],
    destroy => [ 'PVE::API2::LXC', 'destroy_vm', ['vmid'], { node => $nodename }, $upid_exit ],

    start => [ 'PVE::API2::LXC::Status', 'vm_start', ['vmid'], { node => $nodename }, $upid_exit],
    suspend => [ 'PVE::API2::LXC::Status', 'vm_suspend', ['vmid'], { node => $nodename }, $upid_exit],
    resume => [ 'PVE::API2::LXC::Status', 'vm_resume', ['vmid'], { node => $nodename }, $upid_exit],
    shutdown => [ 'PVE::API2::LXC::Status', 'vm_shutdown', ['vmid'], { node => $nodename }, $upid_exit],
    stop => [ 'PVE::API2::LXC::Status', 'vm_stop', ['vmid'], { node => $nodename }, $upid_exit],
    reboot => [ 'PVE::API2::LXC::Status', 'vm_reboot', ['vmid'], { node => $nodename }, $upid_exit],

    clone => [ "PVE::API2::LXC", 'clone_vm', ['vmid', 'newid'], { node => $nodename }, $upid_exit ],
    migrate => [ "PVE::API2::LXC", 'migrate_vm', ['vmid', 'target'], { node => $nodename }, $upid_exit],
    'move-volume' => [ "PVE::API2::LXC", 'move_volume', ['vmid', 'volume', 'storage', 'target-vmid', 'target-volume'], { node => $nodename }, $upid_exit ],
    move_volume => { alias => 'move-volume' },
    'remote-migrate' => [ __PACKAGE__, 'remote_migrate_vm', ['vmid', 'target-vmid', 'target-endpoint'], { node => $nodename }, $upid_exit ],

    snapshot => [ "PVE::API2::LXC::Snapshot", 'snapshot', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],
    delsnapshot => [ "PVE::API2::LXC::Snapshot", 'delsnapshot', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],
    listsnapshot => [ "PVE::API2::LXC::Snapshot", 'list', ['vmid'], { node => $nodename }, \&PVE::GuestHelpers::print_snapshot_tree ],
    rollback => [ "PVE::API2::LXC::Snapshot", 'rollback', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],
    template => [ "PVE::API2::LXC", 'template', ['vmid'], { node => $nodename }],

    status => [ __PACKAGE__, 'status', ['vmid']],
    console => [ __PACKAGE__, 'console', ['vmid']],
    enter => [ __PACKAGE__, 'enter', ['vmid']],
    unlock => [ __PACKAGE__, 'unlock', ['vmid']],
    exec => [ __PACKAGE__, 'exec', ['vmid', 'extra-args']],
    fsck => [ __PACKAGE__, 'fsck', ['vmid']],

    mount => [ __PACKAGE__, 'mount', ['vmid']],
    unmount => [ __PACKAGE__, 'unmount', ['vmid']],
    push => [ __PACKAGE__, 'push', ['vmid', 'file', 'destination']],
    pull => [ __PACKAGE__, 'pull', ['vmid', 'path', 'destination']],

    df => [ __PACKAGE__, 'df', ['vmid']],
    rescan  => [ __PACKAGE__, 'rescan', []],
    cpusets => [ __PACKAGE__, 'cpusets', []],
    fstrim => [ __PACKAGE__, 'fstrim', ['vmid']],
};

1;
