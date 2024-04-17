package PVE::LXC;

use strict;
use warnings;

use Cwd qw();
use Errno qw(ELOOP ENOTDIR EROFS ECONNREFUSED EEXIST);
use Fcntl qw(O_RDONLY O_WRONLY O_NOFOLLOW O_DIRECTORY :mode);
use File::Path;
use File::Spec;
use IO::Poll qw(POLLIN POLLHUP);
use IO::Socket::UNIX;
use POSIX qw(EINTR);
use Socket;
use Time::HiRes qw (gettimeofday);

use PVE::AccessControl;
use PVE::CGroup;
use PVE::CpuSet;
use PVE::Exception qw(raise_perm_exc);
use PVE::GuestHelpers qw(check_vnet_access safe_string_ne safe_num_ne safe_boolean_ne);
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Network;
use PVE::ProcFSTools;
use PVE::RESTEnvironment;
use PVE::SafeSyslog;
use PVE::Storage;
use PVE::Tools qw(
    run_command
    dir_glob_foreach
    file_get_contents
    file_set_contents
    AT_FDCWD
    O_PATH
    $IPV4RE
    $IPV6RE
);
use PVE::Syscall qw(:fsmount);

use PVE::LXC::CGroup;
use PVE::LXC::Config;
use PVE::LXC::Monitor;
use PVE::LXC::Tools;

my $have_sdn;
eval {
    require PVE::Network::SDN::Zones;
    require PVE::Network::SDN::Vnets;
    $have_sdn = 1;
};

my $LXC_CONFIG_PATH = '/usr/share/lxc/config';

my $nodename = PVE::INotify::nodename();

my $cpuinfo= PVE::ProcFSTools::read_cpuinfo();

our $NEW_DISK_RE = qr/^([^:\s]+):(\d+(\.\d+)?)$/;

sub config_list {
    my $vmlist = PVE::Cluster::get_vmlist();
    my $res = {};
    return $res if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};

    foreach my $vmid (keys %$ids) {
	next if !$vmid; # skip CT0
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	next if !$d->{type} || $d->{type} ne 'lxc';
	$res->{$vmid} = { type => 'lxc', vmid => int($vmid) };
    }
    return $res;
}

# container status helpers

sub list_active_containers {

    my $filename = "/proc/net/unix";

    # similar test is used by lcxcontainers.c: list_active_containers
    my $res = {};

    my $fh = IO::File->new ($filename, "r");
    return $res if !$fh;

    while (defined(my $line = <$fh>)) {
	if ($line =~ m/^[a-f0-9]+:\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\d+\s+(\S+)$/) {
	    my $path = $1;
	    if ($path =~ m!^@/var/lib/lxc/(\d+)/command$!) {
		$res->{$1} = 1;
	    }
	}
    }

    close($fh);

    return $res;
}

# warning: this is slow
sub check_running {
    my ($vmid) = @_;

    my $active_hash = list_active_containers();

    return 1 if defined($active_hash->{$vmid});

    return undef;
}

sub get_container_disk_usage {
    my ($vmid, $pid) = @_;

    return PVE::Tools::df("/proc/$pid/root/", 1);
}

my $last_proc_vmid_stat;

our $vmstatus_return_properties = {
    vmid => get_standard_option('pve-vmid'),
    status => {
	description => "LXC Container status.",
	type => 'string',
	enum => ['stopped', 'running'],
    },
    maxmem => {
	description => "Maximum memory in bytes.",
	type => 'integer',
	optional => 1,
	renderer => 'bytes',
    },
    maxswap => {
	description => "Maximum SWAP memory in bytes.",
	type => 'integer',
	optional => 1,
	renderer => 'bytes',
    },
    maxdisk => {
	description => "Root disk size in bytes.",
	type => 'integer',
	optional => 1,
	renderer => 'bytes',
    },
    name => {
	description => "Container name.",
	type => 'string',
	optional => 1,
    },
    uptime => {
	description => "Uptime.",
	type => 'integer',
	optional => 1,
	renderer => 'duration',
    },
    cpus => {
	description => "Maximum usable CPUs.",
	type => 'number',
	optional => 1,
    },
    lock => {
	description => "The current config lock, if any.",
	type => 'string',
	optional => 1,
    },
    tags => {
	description => "The current configured tags, if any.",
	type => 'string',
	optional => 1,
    }
};

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc', vmid => int($opt_vmid) }} : config_list();

    my $active_hash = list_active_containers();

    my $cpucount = $cpuinfo->{cpus} || 1;

    my $cdtime = gettimeofday;

    my $uptime = (PVE::ProcFSTools::read_proc_uptime(1))[0];
    my $clock_ticks = POSIX::sysconf(&POSIX::_SC_CLK_TCK);

    my $unprivileged = {};

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};

	eval { $d->{pid} = int(find_lxc_pid($vmid)) if defined($active_hash->{$vmid}); };
	warn $@ if $@; # ignore errors (consider them stopped)

	$d->{status} = $active_hash->{$vmid} ? 'running' : 'stopped';

	my $cfspath = PVE::LXC::Config->cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	$unprivileged->{$vmid} = $conf->{unprivileged};

	$d->{name} = $conf->{'hostname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;

	$d->{cpus} = $conf->{cores} || $conf->{cpulimit};
	$d->{cpus} = $cpucount if !$d->{cpus};

	$d->{tags} = $conf->{tags} if defined($conf->{tags});

	if ($d->{pid}) {
	    my $res = get_container_disk_usage($vmid, $d->{pid});
	    $d->{disk} = int($res->{used});
	    $d->{maxdisk} = int($res->{total});
	} else {
	    $d->{disk} = 0;
	    # use 4GB by default ??
	    if (my $rootfs = $conf->{rootfs}) {
		my $rootinfo = PVE::LXC::Config->parse_volume('rootfs', $rootfs);
		$d->{maxdisk} = $rootinfo->{size} || (4*1024*1024*1024);
	    } else {
		$d->{maxdisk} = 4*1024*1024*1024;
	    }
	}

	$d->{mem} = 0;
	$d->{swap} = 0;
	$d->{maxmem} = ($conf->{memory}||512)*1024*1024;
	$d->{maxswap} = ($conf->{swap}//0)*1024*1024;

	$d->{uptime} = 0;
	$d->{cpu} = 0;

	$d->{netout} = 0;
	$d->{netin} = 0;

	$d->{diskread} = 0;
	$d->{diskwrite} = 0;

	$d->{template} = 1 if PVE::LXC::Config->is_template($conf);
	$d->{lock} = $conf->{lock} if $conf->{lock};
    }

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};
	my $pid = $d->{pid};

	next if !$pid; # skip stopped CTs

	my $proc_pid_stat = PVE::ProcFSTools::read_proc_pid_stat($pid);
	$d->{uptime} = int(($uptime - $proc_pid_stat->{starttime}) / $clock_ticks); # the method lxcfs uses

	my $unpriv = $unprivileged->{$vmid};

	my $cgroups = PVE::LXC::CGroup->new($vmid);

	if (defined(my $mem = $cgroups->get_memory_stat())) {
	    $d->{mem} = int($mem->{mem});
	    $d->{swap} = int($mem->{swap});
	} else {
	    $d->{mem} = 0;
	    $d->{swap} = 0;
	}

	if (defined(my $blkio = $cgroups->get_io_stats())) {
	    $d->{diskread} = int($blkio->{diskread});
	    $d->{diskwrite} = int($blkio->{diskwrite});
	} else {
	    $d->{diskread} = 0;
	    $d->{diskwrite} = 0;
	}

	if (defined(my $cpu = $cgroups->get_cpu_stat())) {
	    # Total time (in milliseconds) used up by the cpu.
	    my $used_ms = $cpu->{utime} + $cpu->{stime};

	    my $old = $last_proc_vmid_stat->{$vmid};
	    if (!$old) {
		$last_proc_vmid_stat->{$vmid} = {
		    time => $cdtime,
		    used => $used_ms,
		    cpu => 0,
		};
		next;
	    }

	    my $delta_ms = ($cdtime - $old->{time}) * $cpucount * 1000.0;
	    if ($delta_ms > 1000.0) {
		my $delta_used_ms = $used_ms - $old->{used};
		$d->{cpu} = (($delta_used_ms / $delta_ms) * $cpucount) / $d->{cpus};
		$last_proc_vmid_stat->{$vmid} = {
		    time => $cdtime,
		    used => $used_ms,
		    cpu => $d->{cpu},
		};
	    } else {
		$d->{cpu} = $old->{cpu};
	    }
	} else {
	    $d->{cpu} = 0;
	}
    }

    my $netdev = PVE::ProcFSTools::read_proc_net_dev();

    foreach my $dev (keys %$netdev) {
	next if $dev !~ m/^veth([1-9]\d*)i/;
	my $vmid = $1;
	my $d = $list->{$vmid};

	next if !$d;

	$d->{netout} += $netdev->{$dev}->{receive};
	$d->{netin} += $netdev->{$dev}->{transmit};

    }

    return $list;
}

sub find_lxc_console_pids {

    my $res = {};

    PVE::Tools::dir_glob_foreach('/proc', '\d+', sub {
	my ($pid) = @_;

	my $cmdline = PVE::Tools::file_read_firstline("/proc/$pid/cmdline");
	return if !$cmdline;

	my @args = split(/\0/, $cmdline);

	# search for lxc-console -n <vmid>
	return if scalar(@args) != 3;
	return if $args[1] ne '-n';
	return if $args[2] !~ m/^\d+$/;
	return if $args[0] !~ m|^(/usr/bin/)?lxc-console$|;

	my $vmid = $args[2];

	push @{$res->{$vmid}}, $pid;
    });

    return $res;
}

sub find_lxc_pid {
    my ($vmid) = @_;

    my $pid = undef;
    my $parser = sub {
        my $line = shift;
        $pid = $1 if $line =~ m/^PID:\s+(\d+)$/;
    };
    PVE::Tools::run_command(['lxc-info', '-n', $vmid, '-p'], outfunc => $parser);

    die "unable to get PID for CT $vmid (not running?)\n" if !$pid;

    return $pid;
}

sub open_pid_fd($) {
    my ($pid) = @_;
    sysopen(my $fd, "/proc/$pid", O_RDONLY | O_DIRECTORY)
	or die "failed to open /proc/$pid pid fd\n";
    return $fd;
}

sub open_lxc_pid {
    my ($vmid) = @_;

    # Find the pid and open:
    my $pid = find_lxc_pid($vmid);
    my $fd = open_pid_fd($pid);

    # Verify:
    my $pid2 = find_lxc_pid($vmid);

    return () if $pid != $pid2;
    return ($pid, $fd);
}

sub open_ppid {
    my ($pid) = @_;

    # Find the parent pid via proc and open it:
    my $stat = PVE::ProcFSTools::read_proc_pid_stat($pid);
    my $ppid = $stat->{ppid} // die "failed to get parent pid\n";

    my $fd = open_pid_fd($ppid);

    # Verify:
    $stat = PVE::ProcFSTools::read_proc_pid_stat($pid);
    my $ppid2 = $stat->{ppid} // die "failed to get parent pid for verification\n";

    return () if $ppid != $ppid2;
    return ($ppid, $fd);
}

# Note: we cannot use Net:IP, because that only allows strict
# CIDR networks
sub parse_ipv4_cidr {
    my ($cidr, $noerr) = @_;

    if ($cidr =~ m!^($IPV4RE)(?:/(\d+))$! && ($2 > 7) &&  ($2 <= 32)) {
	return { address => $1, netmask => $PVE::Network::ipv4_reverse_mask->[$2] };
    }

    return undef if $noerr;

    die "unable to parse ipv4 address/mask\n";
}

# With seccomp trap to userspace we now have the ability to optionally forward
# certain syscalls to the "host" to handle (via our pve-lxc-syscalld daemon).
#
# This means that there are cases where we need to create an extra seccomp
# profile for the container to load.
#
# This returns a configuration snippet added to the raw lxc config.
sub make_seccomp_config {
    my ($conf, $vmid, $conf_dir, $unprivileged, $features) = @_;
    # User-configured profile has precedence, note that the user's entry would
    # be written 'after' this line anyway...
    if (PVE::LXC::Config->has_lxc_entry($conf, 'lxc.seccomp.profile')) {
	# Warn the user if this conflicts with a feature:
	my $warn = join(', ', grep { $features->{$_} } qw(keyctl mknod));
	warn "explicitly configured lxc.seccomp.profile overrides the following settings: $warn\n"
	    if length($warn) > 0;
	return '';
    }

    # Privileged containers keep using the default (which is already part of
    # the files included via lxc.include, so we don't need to write it out,
    # that way it stays admin-configurable via /usr/share/lxc/config/... as
    # well)
    return '' if !$unprivileged;

    my $rules = {
	keyctl => ['errno 38'],

	# Disable btrfs ioctrls since they don't work particularly well in user namespaces.
	# Particularly, without the mount option to enable rmdir removing snapshots, user
	# namespaces can create snapshots but neither `show` or `delete` them, which is quite
	# horrible, so for now, just disable this entirely:
	#
	# BTRFS_IOCTL_MAGIC 0x94, _IOC type shift is 8,
	# so `(req & 0xFF00) == 0x9400` is a btrfs ioctl and gets an EPERM
	ioctl  => ['errno 1 [1,0x9400,SCMP_CMP_MASKED_EQ,0xff00]'],
    };

    my $raw_conf = '';

    # Unprivileged containers will get keyctl() disabled by default as a
    # workaround for systemd-networkd behavior. But we have an option to
    # explicitly enable it:
    if ($features->{keyctl}) {
	delete $rules->{keyctl};
    }

    # By default, unprivileged containers cannot use `mknod` at all.
    # Since lxc 3.2, we can use seccomp's trap to userspace feature for this,
    # but for now this is experimental, so it has to be enabled via a feature
    # flag.
    # Note that we only handle block and char devices (like lxd), the rest we
    # leave up to the kernel. We may in the future remove this if seccomp gets
    # a way to tell the kernel to "continue" a syscall.
    if ($features->{mknod}) {
	my ($ok, $kernel) = PVE::ProcFSTools::check_kernel_release(5, 3);
	if (!$ok) {
	    die "'mknod' feature requested, but kernel too old (found $kernel, required >= 5.3)\n";
	}

	$raw_conf .= "lxc.seccomp.notify.proxy = unix:/run/pve/lxc-syscalld.sock\n";
	$raw_conf .= "lxc.seccomp.notify.cookie = $vmid\n";

	$rules->{mknod} = [
	    # condition: (mode & S_IFMT) == S_IFCHR
	    'notify [1,8192,SCMP_CMP_MASKED_EQ,61440]',
	    # condition: (mode & S_IFMT) == S_IFBLK
	    'notify [1,24576,SCMP_CMP_MASKED_EQ,61440]',
	];
	$rules->{mknodat} = [
	    # condition: (mode & S_IFMT) == S_IFCHR
	    'notify [2,8192,SCMP_CMP_MASKED_EQ,61440]',
	    # condition: (mode & S_IFMT) == S_IFBLK
	    'notify [2,24576,SCMP_CMP_MASKED_EQ,61440]',
	];
    }

    # Now build the custom seccomp rule text...
    my $extra_rules = join("\n", map {
	my $syscall = $_;
	map { "$syscall $_" } $rules->{$syscall}->@*
    } sort keys %$rules) . "\n";

    return $raw_conf if $extra_rules eq "\n";

    # We still have the "most common" config readily available, so don't write
    # out that one:
    if ($raw_conf eq '' && $extra_rules eq "keyctl errno 38\n") {
	# we have no extra $raw_conf and use the same we had in pve 6.1:
	return "lxc.seccomp.profile = $LXC_CONFIG_PATH/pve-userns.seccomp\n";
    }

    # Write the rule file to the container's config path:
    my $rule_file = "$conf_dir/rules.seccomp";
    my $rule_data = file_get_contents("$LXC_CONFIG_PATH/common.seccomp")
	. $extra_rules;
    file_set_contents($rule_file, $rule_data);
    $raw_conf .= "lxc.seccomp.profile = $rule_file\n";

    return $raw_conf;
}

# Since lxc-3.0.2 we can have lxc generate a profile for the container
# automatically. The default should be equivalent to the old
# `lxc-container-default-cgns` profile.
#
# Additionally this also added `lxc.apparmor.raw` which can be used to inject
# additional lines into the profile. We can use that to allow mounting specific
# file systems.
sub make_apparmor_config {
    my ($conf, $unprivileged, $features) = @_;

    # user-configured profile has precedence, but first we go through our own
    # code to figure out whether we should warn the user:

    my $raw = "lxc.apparmor.profile = generated\n";
    my @profile_uses;

    if ($features->{fuse}) {
	# For the informational warning:
	push @profile_uses, 'features:fuse';
    }

    # There's lxc.apparmor.allow_nesting now, which will add the necessary
    # apparmor lines, create an apparmor namespace for the container, but also
    # adds proc and sysfs mounts to /dev/.lxc/{proc,sys}. These do not have
    # lxcfs mounted over them, because that would prevent the container from
    # mounting new instances of them for nested containers.
    if ($features->{nesting}) {
	push @profile_uses, 'features:nesting';
	$raw .= "lxc.apparmor.allow_nesting = 1\n"
    } else {
	# In the default profile in /etc/apparmor.d we patch this in because
	# otherwise a container can for example run `chown` on /sys, breaking
	# access to it for non-CAP_DAC_OVERRIDE tools on the host:
	$raw .= "lxc.apparmor.raw = deny mount -> /proc/,\n";
	$raw .= "lxc.apparmor.raw = deny mount -> /sys/,\n";
	# Preferably we could use the 'remount' flag but this does not sit well
	# with apparmor_parser currently:
	#  mount options=(rw, nosuid, nodev, noexec, remount) -> /sys/,
    }

    if (my $mount = $features->{mount}) {
	push @profile_uses, 'features:mount';
	foreach my $fs (PVE::Tools::split_list($mount)) {
	    $raw .= "lxc.apparmor.raw = mount fstype=$fs,\n";
	}
    }

    # More to come?

    if (PVE::LXC::Config->has_lxc_entry($conf, 'lxc.apparmor.profile')) {
	if (length(my $used = join(', ', @profile_uses))) {
	    warn "explicitly configured lxc.apparmor.profile overrides the following settings: $used\n";
	}
	return '';
    }

    return $raw;
}

sub update_lxc_config {
    my ($vmid, $conf) = @_;

    my $dir = "/var/lib/lxc/$vmid";

    if ($conf->{template}) {

	unlink "$dir/config";

	return;
    }

    my ($lxc_major, $lxc_minor) = get_lxc_version();

    my $raw = '';

    if ($lxc_major >= 4) {
	# Explicitly don't use relative directories, which is the default, but
	# note that we do this mostly because they are only applied for *some*
	# cgroups. Our pve-container@.service now starts lxc-start with `-F`,
	# so we also don't need to worry about the new monitor cgroup to
	# confuse systemd.
	$raw .= "lxc.cgroup.relative = 0\n";

	# To make things easier, let's keep our previous cgroup layout and
	# simply move the monitor outside:
	$raw .= "lxc.cgroup.dir.monitor = lxc.monitor/$vmid\n";
	# cgroup namespace separation for stronger limits:
	$raw .= "lxc.cgroup.dir.container = lxc/$vmid\n";
	$raw .= "lxc.cgroup.dir.container.inner = ns\n";
    }

    die "missing 'arch' - internal error" if !$conf->{arch};
    $raw .= "lxc.arch = $conf->{arch}\n";

    my $custom_idmap = PVE::LXC::Config->has_lxc_entry($conf, 'lxc.idmap');
    my $unprivileged = $conf->{unprivileged} || $custom_idmap;

    my $ostype = $conf->{ostype} || die "missing 'ostype' - internal error";

    File::Path::mkpath($dir);

    my $cfgpath = '/usr/share/lxc/config';
    my $inc = "$cfgpath/$ostype.common.conf";
    $inc ="$cfgpath/common.conf" if !-f $inc;
    $raw .= "lxc.include = $inc\n";
    if ($unprivileged) {
	$inc = "$cfgpath/$ostype.userns.conf";
	$inc = "$cfgpath/userns.conf" if !-f $inc;
	$raw .= "lxc.include = $inc\n";
    }

    my $features = PVE::LXC::Config->parse_features($conf->{features});

    $raw .= make_seccomp_config($conf, $vmid, $dir, $unprivileged, $features);
    $raw .= make_apparmor_config($conf, $unprivileged, $features);
    if ($features->{fuse}) {
	$raw .= "lxc.apparmor.raw = mount fstype=fuse,\n";
	$raw .= "lxc.mount.entry = /dev/fuse dev/fuse none bind,create=file 0 0\n";
    }

    if ($unprivileged && !$features->{force_rw_sys}) {
	# unpriv. CT default to sys:rw, but that doesn't always plays well with
	# systemd, e.g., systemd-networkd https://systemd.io/CONTAINER_INTERFACE/
	$raw .= "lxc.mount.auto = sys:mixed\n";
    }

    PVE::LXC::Config->foreach_passthrough_device($conf, sub {
	my ($key, $device) = @_;

	die "Path is not defined for passthrough device $key\n"
	    if !defined($device->{path});

	my ($mode, $rdev) = PVE::LXC::Tools::get_device_mode_and_rdev($device->{path});
	my $major = PVE::Tools::dev_t_major($rdev);
	my $minor = PVE::Tools::dev_t_minor($rdev);
	my $device_type_char = S_ISBLK($mode) ? 'b' : 'c';
	$raw .= "lxc.cgroup2.devices.allow = $device_type_char $major:$minor rw\n";
    });

    # WARNING: DO NOT REMOVE this without making sure that loop device nodes
    # cannot be exposed to the container with r/w access (cgroup perms).
    # When this is enabled mounts will still remain in the monitor's namespace
    # after the container unmounted them and thus will not detach from their
    # files while the container is running!
    $raw .= "lxc.monitor.unshare = 1\n";

    my ($cgv1, $cgv2) = PVE::CGroup::get_cgroup_controllers();

    # Should we read them from /etc/subuid?
    if ($unprivileged && !$custom_idmap) {
	$raw .= "lxc.idmap = u 0 100000 65536\n";
	$raw .= "lxc.idmap = g 0 100000 65536\n";
    }

    if (!PVE::LXC::Config->has_dev_console($conf)) {
	$raw .= "lxc.console.path = none\n";
	if ($cgv1->{devices}) {
	    $raw .= "lxc.cgroup.devices.deny = c 5:1 rwm\n";
	} elsif (defined($cgv2)) {
	    $raw .= "lxc.cgroup2.devices.deny = c 5:1 rwm\n";
	}
    }

    my $ttycount = PVE::LXC::Config->get_tty_count($conf);
    $raw .= "lxc.tty.max = $ttycount\n";

    # some init scripts expect a linux terminal (turnkey).
    $raw .= "lxc.environment = TERM=linux\n";

    my $utsname = $conf->{hostname} || "CT$vmid";
    $raw .= "lxc.uts.name = $utsname\n";

    if ($cgv1->{memory}) {
	my $memory = $conf->{memory} || 512;
	my $swap = $conf->{swap} // 0;

	my $lxcmem = int($memory*1024*1024);
	$raw .= "lxc.cgroup.memory.limit_in_bytes = $lxcmem\n";

	my $lxcswap = int(($memory + $swap)*1024*1024);
	$raw .= "lxc.cgroup.memory.memsw.limit_in_bytes = $lxcswap\n";
    } elsif ($cgv2->{memory}) {
	my $memory = $conf->{memory} || 512;
	my $swap = $conf->{swap} // 0;

	# cgroup memory usage is limited by the hard 'max' limit (OOM-killer enforced) and the soft
	# 'high' limit (cgroup processes get throttled and put under heavy reclaim pressure).
	my ($lxc_mem_max, $lxc_mem_high) = PVE::LXC::Config::calculate_memory_constraints($memory);
	$raw .= "lxc.cgroup2.memory.max = $lxc_mem_max\n";
	$raw .= "lxc.cgroup2.memory.high = $lxc_mem_high\n";

	my $lxcswap = int($swap*1024*1024);
	$raw .= "lxc.cgroup2.memory.swap.max = $lxcswap\n";
    }

    if ($cgv1->{cpu}) {
	if (my $cpulimit = $conf->{cpulimit}) {
	    $raw .= "lxc.cgroup.cpu.cfs_period_us = 100000\n";
	    my $value = int(100000*$cpulimit);
	    $raw .= "lxc.cgroup.cpu.cfs_quota_us = $value\n";
	}

	my $shares = PVE::CGroup::clamp_cpu_shares($conf->{cpuunits});
	$raw .= "lxc.cgroup.cpu.shares = $shares\n";
    } elsif ($cgv2->{cpu}) {
	# See PVE::CGroup
	if (my $cpulimit = $conf->{cpulimit}) {
	    my $value = int(100000*$cpulimit);
	    $raw .= "lxc.cgroup2.cpu.max = $value 100000\n";
	}

	if (defined(my $shares = $conf->{cpuunits})) {
	    $shares = PVE::CGroup::clamp_cpu_shares($shares);
	    $raw .= "lxc.cgroup2.cpu.weight = $shares\n";
	}
    }

    die "missing 'rootfs' configuration\n"
	if !defined($conf->{rootfs});

    my $mountpoint = PVE::LXC::Config->parse_volume('rootfs', $conf->{rootfs});

    $raw .= "lxc.rootfs.path = $dir/rootfs\n";

    foreach my $k (sort keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	$raw .= "lxc.net.$ind.type = veth\n";
	$raw .= "lxc.net.$ind.veth.pair = veth${vmid}i${ind}\n";
	$raw .= "lxc.net.$ind.hwaddr = $d->{hwaddr}\n" if defined($d->{hwaddr});
	$raw .= "lxc.net.$ind.name = $d->{name}\n" if defined($d->{name});

	my $bridge_mtu = PVE::Network::read_bridge_mtu($d->{bridge});
	my $mtu = $d->{mtu} || $bridge_mtu;

	# Keep container from starting with invalid mtu configuration
	die "$k: MTU size '$mtu' is bigger than bridge MTU '$bridge_mtu'\n"
	    if ($mtu > $bridge_mtu);

	$raw .= "lxc.net.$ind.mtu = $mtu\n";

	# Starting with lxc 4.0, we do not patch lxc to execute our up-scripts.
	if ($lxc_major >= 4) {
	    $raw .= "lxc.net.$ind.script.up = /usr/share/lxc/lxcnetaddbr\n";
	}
    }

    my $had_cpuset = 0;
    if (my $lxcconf = $conf->{lxc}) {
	foreach my $entry (@$lxcconf) {
	    my ($k, $v) = @$entry;
	    $had_cpuset = 1 if $k eq 'lxc.cgroup.cpuset.cpus' || $k eq 'lxc.cgroup2.cpuset.cpus';
	    $raw .= "$k = $v\n";
	}
    }

    my $cpuset;
    my ($cpuset_cgroup, $cpuset_version) = eval { PVE::CGroup::cpuset_controller_path() };
    if (defined($cpuset_cgroup)) {
	$cpuset = eval { PVE::CpuSet->new_from_path("$cpuset_cgroup/lxc", 1) }
	    || PVE::CpuSet->new_from_path($cpuset_cgroup, 1);
    }
    my $cores = $conf->{cores};
    if (!$had_cpuset && $cores && $cpuset) {
	my @members = $cpuset->members();
	while (scalar(@members) > $cores) {
	    my $randidx = int(rand(scalar(@members)));
	    $cpuset->delete($members[$randidx]);
	    splice(@members, $randidx, 1); # keep track of the changes
	}
	my $ver = $cpuset_version == 1 ? '' : '2';
	$raw .= "lxc.cgroup$ver.cpuset.cpus = ".$cpuset->short_string()."\n";
    }

    File::Path::mkpath("$dir/rootfs");

    PVE::Tools::file_set_contents("$dir/config", $raw);
}

# verify and cleanup nameserver list (replace \0 with ' ')
sub verify_nameserver_list {
    my ($nameserver_list) = @_;

    my @list = ();
    foreach my $server (PVE::Tools::split_list($nameserver_list)) {
	PVE::LXC::Config::verify_ip_with_ll_iface($server);
	push @list, $server;
    }

    return join(' ', @list);
}

sub verify_searchdomain_list {
    my ($searchdomain_list) = @_;

    my @list = ();
    foreach my $server (PVE::Tools::split_list($searchdomain_list)) {
	# todo: should we add checks for valid dns domains?
	push @list, $server;
    }

    return join(' ', @list);
}

sub get_console_command {
    my ($vmid, $conf, $escapechar) = @_;

    # '-1' as $escapechar disables keyboard escape sequence
    # any other passed char (a-z) will result in <Ctrl+$escapechar q>

    my $cmode = PVE::LXC::Config->get_cmode($conf);

    my $cmd = [];
    if ($cmode eq 'console') {
	push @$cmd, 'lxc-console', '-n',  $vmid, '-t', 0;
	push @$cmd, '-e', $escapechar if $escapechar;
    } elsif ($cmode eq 'tty') {
	push @$cmd, 'lxc-console', '-n',  $vmid;
	push @$cmd, '-e', $escapechar if $escapechar;
    } elsif ($cmode eq 'shell') {
	push @$cmd, 'lxc-attach', '--clear-env', '-n', $vmid;
    } else {
	die "internal error";
    }

    return $cmd;
}

sub get_primary_ips {
    my ($conf) = @_;

    # return data from net0

    return undef if !defined($conf->{net0});
    my $net = PVE::LXC::Config->parse_lxc_network($conf->{net0});

    my $ipv4 = $net->{ip};
    if ($ipv4) {
	if ($ipv4 =~ /^(dhcp|manual)$/) {
	    $ipv4 = undef
	} else {
	    $ipv4 =~ s!/\d+$!!;
	}
    }
    my $ipv6 = $net->{ip6};
    if ($ipv6) {
	if ($ipv6 =~ /^(auto|dhcp|manual)$/) {
	    $ipv6 = undef;
	} else {
	    $ipv6 =~ s!/\d+$!!;
	}
    }

    return ($ipv4, $ipv6);
}

sub delete_mountpoint_volume {
    my ($storage_cfg, $vmid, $volume) = @_;

    return if PVE::LXC::Config->classify_mountpoint($volume) ne 'volume';

    my ($vtype, $name, $owner) = PVE::Storage::parse_volname($storage_cfg, $volume);

    if ($vmid == $owner) {
	PVE::Storage::vdisk_free($storage_cfg, $volume);
    } else {
	warn "ignore deletion of '$volume', CT $vmid isn't the owner!\n";
    }
}

sub destroy_lxc_container {
    my ($storage_cfg, $vmid, $conf, $replacement_conf, $purge_unreferenced) = @_;

    my $volids = {};
    my $remove_volume = sub {
	my ($ms, $mountpoint) = @_;

	my $volume = $mountpoint->{volume};

	return if $volids->{$volume};
	$volids->{$volume} = 1;

	delete_mountpoint_volume($storage_cfg, $vmid, $volume);
    };
    PVE::LXC::Config->foreach_volume_full($conf, {include_unused => 1}, $remove_volume);

    PVE::LXC::Config->foreach_volume_full($conf->{pending}, {include_unused => 1}, $remove_volume);

    if ($purge_unreferenced) { # also remove unreferenced disk
	my $vmdisks = PVE::Storage::vdisk_list($storage_cfg, undef, $vmid, undef, 'rootdir');
	PVE::Storage::foreach_volid($vmdisks, sub {
	    my ($volid, $sid, $volname, $d) = @_;
	    eval { PVE::Storage::vdisk_free($storage_cfg, $volid) };
	    warn $@ if $@;
	});
    }

    delete_ifaces_ipams_ips($conf, $vmid);

    rmdir "/var/lib/lxc/$vmid/rootfs";
    unlink "/var/lib/lxc/$vmid/config";
    rmdir "/var/lib/lxc/$vmid";
    if (defined $replacement_conf) {
	PVE::LXC::Config->write_config($vmid, $replacement_conf);
    } else {
	PVE::LXC::Config->destroy_config($vmid);
    }
}

sub vm_stop_cleanup {
    my ($storage_cfg, $vmid, $conf, $keepActive) = @_;

    return if $keepActive;

    eval {
	my $vollist = PVE::LXC::Config->get_vm_volumes($conf);
	PVE::Storage::deactivate_volumes($storage_cfg, $vollist);
    };
    warn $@ if $@; # avoid errors - just warn
}

sub net_tap_plug : prototype($$) {
    my ($iface, $net) = @_;

    if (defined($net->{link_down})) {
	PVE::Tools::run_command(['/sbin/ip', 'link', 'set', 'dev', $iface, 'down']);
	# Don't add disconnected interfaces to the bridge, otherwise e.g. applying any network
	# change (e.g. `ifreload -a`) could (re-)activate it unintentionally.
	return;
    }

    my ($bridge, $tag, $firewall, $trunks, $rate, $hwaddr) =
	$net->@{'bridge', 'tag', 'firewall', 'trunks', 'rate', 'hwaddr'};

    if ($have_sdn) {
	PVE::Network::SDN::Zones::tap_plug($iface, $bridge, $tag, $firewall, $trunks, $rate);
	PVE::Network::SDN::Zones::add_bridge_fdb($iface, $hwaddr, $bridge);
    } else {
	PVE::Network::tap_plug($iface, $bridge, $tag, $firewall, $trunks, $rate, { mac => $hwaddr });
    }

    PVE::Tools::run_command(['/sbin/ip', 'link', 'set', 'dev', $iface, 'up']);
}

sub update_net {
    my ($vmid, $conf, $opt, $newnet, $netid, $rootdir) = @_;

    if ($newnet->{type} ne 'veth') {
	# for when there are physical interfaces
	die "cannot update interface of type $newnet->{type}";
    }

    my $veth = "veth${vmid}i${netid}";
    my $eth = $newnet->{name};

    if (my $oldnetcfg = $conf->{$opt}) {
	my $oldnet = PVE::LXC::Config->parse_lxc_network($oldnetcfg);

	if (safe_string_ne($oldnet->{hwaddr}, $newnet->{hwaddr}) ||
	    safe_string_ne($oldnet->{name}, $newnet->{name})) {

	    PVE::Network::veth_delete($veth);

	    if ($have_sdn && safe_string_ne($oldnet->{hwaddr}, $newnet->{hwaddr})) {
		eval { PVE::Network::SDN::Vnets::del_ips_from_mac($oldnet->{bridge}, $oldnet->{hwaddr}, $conf->{hostname}) };
		warn $@ if $@;

		PVE::Network::SDN::Vnets::add_next_free_cidr($newnet->{bridge}, $conf->{hostname}, $newnet->{hwaddr}, $vmid, undef, 1);
		PVE::Network::SDN::Vnets::add_dhcp_mapping($newnet->{bridge}, $newnet->{hwaddr}, $vmid, $conf->{hostname});
	    }

	    delete $conf->{$opt};
	    PVE::LXC::Config->write_config($vmid, $conf);

	    hotplug_net($vmid, $conf, $opt, $newnet, $netid);

	} else {
	    my $bridge_changed = safe_string_ne($oldnet->{bridge}, $newnet->{bridge});

	    if ($bridge_changed ||
		safe_num_ne($oldnet->{tag}, $newnet->{tag}) ||
		safe_num_ne($oldnet->{firewall}, $newnet->{firewall}) ||
		safe_boolean_ne($oldnet->{link_down}, $newnet->{link_down})
	    ) {
		if ($oldnet->{bridge}) {
		    my $oldbridge = $oldnet->{bridge};

		    PVE::Network::tap_unplug($veth);
		    foreach (qw(bridge tag firewall)) {
			delete $oldnet->{$_};
		    }
		    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($oldnet);
		    PVE::LXC::Config->write_config($vmid, $conf);

		    if ($have_sdn && $bridge_changed) {
			eval { PVE::Network::SDN::Vnets::del_ips_from_mac($oldbridge, $oldnet->{hwaddr}, $conf->{hostname}) };
			warn $@ if $@;
		    }
		}

		if ($have_sdn && $bridge_changed) {
		    PVE::Network::SDN::Vnets::add_next_free_cidr($newnet->{bridge}, $conf->{hostname}, $newnet->{hwaddr}, $vmid, undef, 1);
		}
		PVE::LXC::net_tap_plug($veth, $newnet);

		# This includes the rate:
		foreach (qw(bridge tag firewall rate link_down)) {
		    $oldnet->{$_} = $newnet->{$_} if $newnet->{$_};
		}
	    } elsif (safe_string_ne($oldnet->{rate}, $newnet->{rate})) {
		# Rate can be applied on its own but any change above needs to
		# include the rate in tap_plug since OVS resets everything.
		PVE::Network::tap_rate_limit($veth, $newnet->{rate});
		$oldnet->{rate} = $newnet->{rate}
	    }
	    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($oldnet);
	    PVE::LXC::Config->write_config($vmid, $conf);
	}
    } else {
	if ($have_sdn) {
	    PVE::Network::SDN::Vnets::add_next_free_cidr($newnet->{bridge}, $conf->{hostname}, $newnet->{hwaddr}, $vmid, undef, 1);
	    PVE::Network::SDN::Vnets::add_dhcp_mapping($newnet->{bridge}, $newnet->{hwaddr}, $vmid, $conf->{hostname});
	}

	hotplug_net($vmid, $conf, $opt, $newnet, $netid);
    }

    update_ipconfig($vmid, $conf, $opt, $eth, $newnet, $rootdir);
}

sub hotplug_net {
    my ($vmid, $conf, $opt, $newnet, $netid) = @_;

    my $veth = "veth${vmid}i${netid}";
    my $vethpeer = $veth . "p";
    my $eth = $newnet->{name};

    if ($have_sdn) {
	PVE::Network::SDN::Zones::veth_create($veth, $vethpeer, $newnet->{bridge}, $newnet->{hwaddr});
    } else {
	PVE::Network::veth_create($veth, $vethpeer, $newnet->{bridge}, $newnet->{hwaddr});
    }

    PVE::LXC::net_tap_plug($veth, $newnet);

    # attach peer in container
    my $cmd = ['lxc-device', '-n', $vmid, 'add', $vethpeer, "$eth" ];
    PVE::Tools::run_command($cmd);

    # link up peer in container
    $cmd = ['lxc-attach', '-n', $vmid, '-s', 'NETWORK', '--', '/sbin/ip', 'link', 'set', $eth ,'up'  ];
    PVE::Tools::run_command($cmd);

    my $done = { type => 'veth' };
    foreach (qw(bridge tag firewall hwaddr name link_down)) {
	$done->{$_} = $newnet->{$_} if $newnet->{$_};
    }
    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($done);

    PVE::LXC::Config->write_config($vmid, $conf);
}

sub get_interfaces {
    my ($vmid) = @_;

    my $pid = eval { find_lxc_pid($vmid); };
    return if $@;

    my $output;
    # enters the network namespace of the container and executes 'ip a'
    run_command(['nsenter', '-t', $pid, '--net', '--', 'ip', '--json', 'a'],
	outfunc => sub { $output .= shift; });

    my $config = JSON::decode_json($output);

    my $res;
    for my $interface ($config->@*) {
	my $obj = { name => $interface->{ifname} };
	for my $ip ($interface->{addr_info}->@*) {
	    $obj->{$ip->{family}} = $ip->{local} . "/" . $ip->{prefixlen};
	}
	$obj->{hwaddr} = $interface->{address};
	push @$res, $obj
    }

    return $res;
}

sub update_ipconfig {
    my ($vmid, $conf, $opt, $eth, $newnet, $rootdir) = @_;

    my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir);

    my $optdata = PVE::LXC::Config->parse_lxc_network($conf->{$opt});
    my $deleted = [];
    my $added = [];
    my $nscmd = sub {
	my $cmdargs = shift;
	PVE::Tools::run_command(['lxc-attach', '-n', $vmid, '-s', 'NETWORK', '--', @_], %$cmdargs);
    };
    my $ipcmd = sub { &$nscmd({}, '/sbin/ip', @_) };

    my $change_ip_config = sub {
	my ($ipversion) = @_;

	my $family_opt = "-$ipversion";
	my $suffix = $ipversion == 4 ? '' : $ipversion;
	my $gw= "gw$suffix";
	my $ip= "ip$suffix";

	my $newip = $newnet->{$ip};
	my $newgw = $newnet->{$gw};
	my $oldip = $optdata->{$ip};
	my $oldgw = $optdata->{$gw};

	my $change_ip = safe_string_ne($oldip, $newip);
	my $change_gw = safe_string_ne($oldgw, $newgw);

	return if !$change_ip && !$change_gw;

	# step 1: add new IP, if this fails we cancel
	my $is_real_ip = ($newip && $newip !~ /^(?:auto|dhcp|manual)$/);
	if ($change_ip && $is_real_ip) {
	    eval { &$ipcmd($family_opt, 'addr', 'add', $newip, 'dev', $eth); };
	    if (my $err = $@) {
		warn $err;
		return;
	    }
	}

	# step 2: replace gateway
	#   If this fails we delete the added IP and cancel.
	#   If it succeeds we save the config and delete the old IP, ignoring
	#   errors. The config is then saved.
	# Note: 'ip route replace' can add
	if ($change_gw) {
	    if ($newgw) {
		eval {
		    if ($is_real_ip && !PVE::Network::is_ip_in_cidr($newgw, $newip, $ipversion)) {
			&$ipcmd($family_opt, 'route', 'add', $newgw, 'dev', $eth);
		    }
		    &$ipcmd($family_opt, 'route', 'replace', 'default', 'via', $newgw);
		};
		if (my $err = $@) {
		    warn $err;
		    # the route was not replaced, the old IP is still available
		    # rollback (delete new IP) and cancel
		    if ($change_ip) {
			eval { &$ipcmd($family_opt, 'addr', 'del', $newip, 'dev', $eth); };
			warn $@ if $@; # no need to die here
		    }
		    return;
		}
	    } else {
		eval { &$ipcmd($family_opt, 'route', 'del', 'default'); };
		# if the route was not deleted, the guest might have deleted it manually
		# warn and continue
		warn $@ if $@;
	    }
	    if ($oldgw && $oldip && !PVE::Network::is_ip_in_cidr($oldgw, $oldip)) {
		eval { &$ipcmd($family_opt, 'route', 'del', $oldgw, 'dev', $eth); };
		# warn if the route was deleted manually
		warn $@ if $@;
	    }
	}

	# from this point on we save the configuration
	# step 3: delete old IP ignoring errors
	if ($change_ip && $oldip && $oldip !~ /^(?:auto|dhcp)$/) {
	    # We need to enable promote_secondaries, otherwise our newly added
	    # address will be removed along with the old one.
	    my $promote = 0;
	    eval {
		if ($ipversion == 4) {
		    &$nscmd({ outfunc => sub { $promote = int(shift) } },
			    'cat', "/proc/sys/net/ipv4/conf/$eth/promote_secondaries");
		    &$nscmd({}, 'sysctl', "net.ipv4.conf.$eth.promote_secondaries=1");
		}
		&$ipcmd($family_opt, 'addr', 'del', $oldip, 'dev', $eth);
	    };
	    warn $@ if $@; # no need to die here

	    if ($ipversion == 4) {
		&$nscmd({}, 'sysctl', "net.ipv4.conf.$eth.promote_secondaries=$promote");
	    }
	}

	foreach my $property ($ip, $gw) {
	    if ($newnet->{$property}) {
		$optdata->{$property} = $newnet->{$property};
	    } else {
		delete $optdata->{$property};
	    }
	}
	$conf->{$opt} = PVE::LXC::Config->print_lxc_network($optdata);
	PVE::LXC::Config->write_config($vmid, $conf);
	$lxc_setup->setup_network($conf);
    };

    &$change_ip_config(4);
    &$change_ip_config(6);

}

my $open_namespace = sub {
    my ($vmid, $pid, $kind) = @_;
    sysopen my $fd, "/proc/$pid/ns/$kind", O_RDONLY
	or die "failed to open $kind namespace of container $vmid: $!\n";
    return $fd;
};

my $enter_namespace = sub {
    my ($vmid, $pid, $kind, $type) = @_;
    my $fd = $open_namespace->($vmid, $pid, $kind);
    PVE::Tools::setns(fileno($fd), $type)
	or die "failed to enter $kind namespace of container $vmid: $!\n";
    close $fd;
};

my $get_container_namespace = sub {
    my ($vmid, $pid, $kind) = @_;

    my $pidfd;
    if (!defined($pid)) {
	# Pin the pid while we're grabbing its stuff from /proc
	($pid, $pidfd) = open_lxc_pid($vmid)
	    or die "failed to open pidfd of container $vmid\'s init process\n";
    }

    return $open_namespace->($vmid, $pid, $kind);
};

my $do_syncfs = sub {
    my ($vmid, $pid, $socket) = @_;

    &$enter_namespace($vmid, $pid, 'mnt', PVE::Tools::CLONE_NEWNS);

    # Tell the parent process to start reading our /proc/mounts
    print {$socket} "go\n";
    $socket->flush();

    # Receive /proc/self/mounts
    my $mountdata = do { local $/ = undef; <$socket> };
    close $socket;

    my %nosyncfs = (
	cgroup => 1,
	cgroup2 => 1,
	devtmpfs => 1,
	devpts => 1,
	'fuse.lxcfs' => 1,
	fusectl => 1,
	mqueue => 1,
	proc => 1,
	sysfs => 1,
	tmpfs => 1,
    );

    # Now sync all mountpoints...
    my $mounts = PVE::ProcFSTools::parse_mounts($mountdata);
    foreach my $mp (@$mounts) {
	my ($what, $dir, $fs) = @$mp;
	next if $nosyncfs{$fs};
	eval { PVE::Tools::sync_mountpoint($dir); };
	warn $@ if $@;
    }
};

sub sync_container_namespace {
    my ($vmid) = @_;
    my $pid = find_lxc_pid($vmid);

    # SOCK_DGRAM is nicer for barriers but cannot be slurped
    socketpair my $pfd, my $cfd, AF_UNIX, SOCK_STREAM, PF_UNSPEC
	or die "failed to create socketpair: $!\n";

    my $child = fork();
    die "fork failed: $!\n" if !defined($child);

    if (!$child) {
	eval {
	    close $pfd;
	    &$do_syncfs($vmid, $pid, $cfd);
	};
	if (my $err = $@) {
	    warn $err;
	    POSIX::_exit(1);
	}
	POSIX::_exit(0);
    }
    close $cfd;
    my $go = <$pfd>;
    die "failed to enter container namespace\n" if $go ne "go\n";

    open my $mounts, '<', "/proc/$child/mounts"
	or die "failed to open container's /proc/mounts: $!\n";
    my $mountdata = do { local $/ = undef; <$mounts> };
    close $mounts;
    print {$pfd} $mountdata;
    close $pfd;

    while (waitpid($child, 0) != $child) {}
    die "failed to sync container namespace\n" if $? != 0;
}

sub template_create {
    my ($vmid, $conf) = @_;

    my $storecfg = PVE::Storage::config();

    PVE::LXC::Config->foreach_volume($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};

	die "Template feature is not available for '$volid'\n"
	    if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);
    });

    PVE::LXC::Config->foreach_volume($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};

	PVE::Storage::activate_volumes($storecfg, [$volid]);

	my $template_volid = PVE::Storage::vdisk_create_base($storecfg, $volid);
	$mountpoint->{volume} = $template_volid;
	$conf->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq "rootfs");
    });

    PVE::LXC::Config->write_config($vmid, $conf);
}

sub check_ct_modify_config_perm {
    my ($rpcenv, $authuser, $vmid, $pool, $oldconf, $newconf, $delete, $unprivileged) = @_;

    return 1 if $authuser eq 'root@pam';
    my $storage_cfg = PVE::Storage::config();

    my $check = sub {
	my ($opt, $delete) = @_;
	if ($opt eq 'cores' || $opt eq 'cpuunits' || $opt eq 'cpulimit') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'rootfs' || $opt =~ /^mp\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	    return if $delete;
	    my $data = PVE::LXC::Config->parse_volume($opt, $newconf->{$opt});
	    raise_perm_exc("mount point type $data->{type} is only allowed for root\@pam")
		if $data->{type} ne 'volume';
	    my $volid = $data->{volume};
	    if ($volid =~ $NEW_DISK_RE) {
		my $sid = $1;
		$rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);
	    } else {
		PVE::Storage::check_volume_access(
		    $rpcenv,
		    $authuser,
		    $storage_cfg,
		    $vmid,
		    $volid,
		    'rootdir',
		);
	    }
	} elsif ($opt eq 'memory' || $opt eq 'swap') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt =~ m/^net\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	    check_bridge_access($rpcenv, $authuser, $oldconf->{$opt}) if $oldconf->{$opt};
	    check_bridge_access($rpcenv, $authuser, $newconf->{$opt}) if $newconf->{$opt};
	} elsif ($opt =~ m/^dev\d+$/) {
	    raise_perm_exc("configuring device passthrough is only allowed for root\@pam");
	} elsif ($opt eq 'nameserver' || $opt eq 'searchdomain' || $opt eq 'hostname') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} elsif ($opt eq 'features') {
	    raise_perm_exc("changing feature flags for privileged container is only allowed for root\@pam")
		if !$unprivileged;

	    my $nesting_changed = 0;
	    my $other_changed = 0;
	    if (!$delete) {
		my $features = PVE::LXC::Config->parse_features($newconf->{$opt});
		if (defined($oldconf) && $oldconf->{$opt}) {
		    # existing container with features
		    my $old_features = PVE::LXC::Config->parse_features($oldconf->{$opt});
		    for my $feature ((keys %$old_features, keys %$features)) {
			my $old = $old_features->{$feature} // '';
			my $new = $features->{$feature} // '';
			if ($old ne $new) {
			    if ($feature eq 'nesting') {
				$nesting_changed = 1;
				next;
			    } else {
				$other_changed = 1;
				last;
			    }
			}
		    }
		} else {
		    # new container or no features defined
		    if (scalar(keys %$features) == 1 && $features->{nesting}) {
			$nesting_changed = 1;
		    } elsif (scalar(keys %$features) > 0) {
			$other_changed = 1;
		    }
		}
	    } else {
		my $features = PVE::LXC::Config->parse_features($oldconf->{$opt});
		if (scalar(keys %$features) == 1 && $features->{nesting}) {
		    $nesting_changed = 1;
		} elsif (scalar(keys %$features) > 0) {
		    $other_changed = 1;
		}
	    }
	    raise_perm_exc("changing feature flags (except nesting) is only allowed for root\@pam")
		if $other_changed;
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Allocate'])
		if $nesting_changed;
	} elsif ($opt eq 'hookscript') {
	    # For now this is restricted to root@pam
	    raise_perm_exc("changing the hookscript is only allowed for root\@pam");
	} elsif ($opt eq 'tags') {
	    my $old = $oldconf->{$opt};
	    my $new = $delete ? '' : $newconf->{$opt};
	    PVE::GuestHelpers::assert_tag_permissions($vmid, $old, $new, $rpcenv, $authuser);
	} else {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Options']);
	}
    };

    foreach my $opt (keys %$newconf) {
	&$check($opt, 0);
    }
    foreach my $opt (@$delete) {
	&$check($opt, 1);
    }

    return 1;
}

sub check_bridge_access {
    my ($rpcenv, $authuser, $raw) = @_;

    return 1 if $authuser eq 'root@pam';

    my $net = PVE::LXC::Config->parse_lxc_network($raw);
    my ($bridge, $tag, $trunks) = $net->@{'bridge', 'tag', 'trunks'};
    check_vnet_access($rpcenv, $authuser, $bridge, $tag, $trunks);

    return 1;
};

sub umount_all {
    my ($vmid, $storage_cfg, $conf, $noerr) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    my $volid_list = PVE::LXC::Config->get_vm_volumes($conf);

    my $res = 1;

    PVE::LXC::Config->foreach_volume_full($conf, {'reverse' => 1}, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};
	my $mount = $mountpoint->{mp};

	return if !$volid || !$mount;

	my $mount_path = "$rootdir/$mount";
	$mount_path =~ s!/+!/!g;

	return if !PVE::ProcFSTools::is_mounted($mount_path);

	eval {
	    PVE::Tools::run_command(['umount', '-d', $mount_path]);
	};
	if (my $err = $@) {
	    if ($noerr) {
		$res = 0;
		warn $err;
	    } else {
		die $err;
	    }
	}
    });

    return $res; # tell caller if (some) umounts failed for the noerr case
}

sub mount_all {
    my ($vmid, $storage_cfg, $conf, $ignore_ro) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    File::Path::make_path($rootdir);

    my $volid_list = PVE::LXC::Config->get_vm_volumes($conf);
    PVE::Storage::activate_volumes($storage_cfg, $volid_list);

    my (undef, $rootuid, $rootgid) = parse_id_maps($conf);

    eval {
	PVE::LXC::Config->foreach_volume($conf, sub {
	    my ($ms, $mountpoint) = @_;

	    $mountpoint->{ro} = 0 if $ignore_ro;

	    mountpoint_mount($mountpoint, $rootdir, $storage_cfg, undef, $rootuid, $rootgid);
        });
    };
    if (my $err = $@) {
	warn "mounting container failed\n";
	umount_all($vmid, $storage_cfg, $conf, 1);
	die $err;
    }

    return $rootdir;
}


sub mountpoint_mount_path {
    my ($mountpoint, $storage_cfg, $snapname) = @_;

    return mountpoint_mount($mountpoint, undef, $storage_cfg, $snapname);
}

sub query_loopdev {
    my ($path) = @_;
    my $found;
    my $parser = sub {
	my $line = shift;
	if ($line =~ m@^(/dev/loop\d+):@) {
	    $found = $1;
	}
    };
    my $cmd = ['losetup', '--associated', $path];
    PVE::Tools::run_command($cmd, outfunc => $parser);
    return $found;
}

# Run a function with a file attached to a loop device.
# The loop device is always detached afterwards (or set to autoclear).
# Returns the loop device.
sub run_with_loopdev {
    my ($func, $file, $readonly) = @_;
    my $device = query_loopdev($file);
    # Try to reuse an existing device
    if ($device) {
	# We assume that whoever setup the loop device is responsible for
	# detaching it.
	&$func($device);
	return $device;
    }

    my $parser = sub {
	my $line = shift;
	if ($line =~ m@^(/dev/loop\d+)$@) {
	    $device = $1;
	}
    };
    my $losetup_cmd = [
	'losetup',
	'--show',
	'-f',
	$file,
    ];
    push @$losetup_cmd, '-r' if $readonly;
    PVE::Tools::run_command($losetup_cmd, outfunc => $parser);
    die "failed to setup loop device for $file\n" if !$device;
    eval { &$func($device); };
    my $err = $@;
    PVE::Tools::run_command(['losetup', '-d', $device]);
    die $err if $err;
    return $device;
}

# In scalar mode: returns a file handle to the deepest directory node.
# In list context: returns a list of:
#   * the deepest directory node
#   * the 2nd deepest directory (parent of the above)
#   * directory name of the last directory
# So that the path $2/$3 should lead to $1 afterwards.
sub walk_tree_nofollow($$$;$$) {
    my ($start, $subdir, $mkdir, $rootuid, $rootgid) = @_;

    sysopen(my $fd, $start, O_PATH | O_DIRECTORY)
	or die "failed to open start directory $start: $!\n";

    return walk_tree_nofollow_fd($start, $fd, $subdir, $mkdir, $rootuid, $rootgid);
}


sub walk_tree_nofollow_fd($$$$;$$) {
    my ($start_dirname, $start_fd, $subdir, $mkdir, $rootuid, $rootgid) = @_;

    # splitdir() returns '' for empty components including the leading /
    my @comps = grep { length($_)>0 } File::Spec->splitdir($subdir);

    my $fd = $start_fd;
    my $dir = $start_dirname;
    my $last_component = undef;
    my $second = $fd;
    foreach my $component (@comps) {
	$dir .= "/$component";
	my $next = PVE::Tools::openat(fileno($fd), $component, O_NOFOLLOW | O_DIRECTORY);

	if (!$next) {
	    # failed, check for symlinks and try to create the path
	    die "symlink encountered at: $dir\n" if $! == ELOOP || $! == ENOTDIR;
	    die "cannot open directory $dir: $!\n" if !$mkdir;

	    # We don't check for errors on mkdirat() here and just try to
	    # openat() again, since at least one error (EEXIST) is an
	    # expected possibility if multiple containers start
	    # simultaneously. If someone else injects a symlink now then
	    # the subsequent openat() will fail due to O_NOFOLLOW anyway.
	    PVE::Tools::mkdirat(fileno($fd), $component, 0755);

	    $next = PVE::Tools::openat(fileno($fd), $component, O_NOFOLLOW | O_DIRECTORY);
	    die "failed to create path: $dir: $!\n" if !$next;

	    PVE::Tools::fchownat(fileno($next), '', $rootuid, $rootgid, PVE::Tools::AT_EMPTY_PATH)
		if defined($rootuid) && defined($rootgid);
	}

	close $second if defined($last_component) && $second != $start_fd;
	$last_component = $component;
	$second = $fd;
	$fd = $next;
    }

    return ($fd, defined($last_component) && $second, $last_component) if wantarray;
    close $second if defined($last_component) && $second != $start_fd;
    return $fd;
}

# To guard against symlink attack races against other currently running
# containers with shared recursive bind mount hierarchies we prepare a
# directory handle for the directory we're mounting over to verify the
# mountpoint afterwards.
sub __bindmount_prepare {
    my ($hostroot, $dir) = @_;
    my $srcdh = walk_tree_nofollow($hostroot, $dir, 0);
    return $srcdh;
}

# Assuming we mount to rootfs/a/b/c, verify with the directory handle to 'b'
# ($parentfd) that 'b/c' (openat($parentfd, 'c')) really leads to the directory
# we intended to bind mount.
sub __bindmount_verify {
    my ($srcdh, $parentfd, $last_dir, $ro) = @_;
    my $destdh;
    if ($parentfd) {
	# Open the mount point path coming from the parent directory since the
	# filehandle we would have gotten as first result of walk_tree_nofollow
	# earlier is still a handle to the underlying directory instead of the
	# mounted path.
	$destdh = PVE::Tools::openat(fileno($parentfd), $last_dir, PVE::Tools::O_PATH | O_NOFOLLOW | O_DIRECTORY);
	die "failed to open mount point: $!\n" if !$destdh;
	if ($ro) {
	    my $dot = '.';
	    # no separate function because 99% of the time it's the wrong thing to use.
	    if (syscall(PVE::Syscall::faccessat, fileno($destdh), $dot, &POSIX::W_OK, 0) != -1) {
		die "failed to mark bind mount read only\n";
	    }
	    die "read-only check failed: $!\n" if $! != EROFS;
	}
    } else {
	# For the rootfs we don't have a parentfd so we open the path directly.
	# Note that this means bindmounting any prefix of the host's
	# /var/lib/lxc/$vmid path into another container is considered a grave
	# security error.
	sysopen $destdh, $last_dir, O_PATH | O_DIRECTORY;
	die "failed to open mount point: $!\n" if !$destdh;
    }

    my ($srcdev, $srcinode) = stat($srcdh);
    my ($dstdev, $dstinode) = stat($destdh);
    close $srcdh;
    close $destdh;

    return ($srcdev == $dstdev && $srcinode == $dstinode);
}

# Perform the actual bind mounting:
sub __bindmount_do {
    my ($dir, $dest, $ro, @extra_opts) = @_;
    PVE::Tools::run_command(['mount', '-o', 'bind', @extra_opts, $dir, $dest]);
    if ($ro) {
	eval { PVE::Tools::run_command(['mount', '-o', 'bind,remount,ro', $dest]); };
	if (my $err = $@) {
	    warn "bindmount error\n";
	    # don't leave writable bind-mounts behind...
	    PVE::Tools::run_command(['umount', $dest]);
	    die $err;
	}
    }
}

sub bindmount {
    my ($dir, $parentfd, $last_dir, $dest, $ro, @extra_opts) = @_;

    my $srcdh = __bindmount_prepare('/', $dir);

    __bindmount_do($dir, $dest, $ro, @extra_opts);

    if (!__bindmount_verify($srcdh, $parentfd, $last_dir, $ro)) {
	PVE::Tools::run_command(['umount', $dest]);
	die "detected mount path change at: $dir\n";
    }
}

# Cleanup $rootdir a bit (double and trailing slashes), build the mount path
# from $rootdir and $mount and walk the path from $rootdir to the final
# directory to check for symlinks.
sub __mount_prepare_rootdir {
    my ($rootdir, $mount, $rootuid, $rootgid) = @_;
    $rootdir =~ s!/+!/!g;
    $rootdir =~ s!/+$!!;
    my $mount_path = "$rootdir/$mount";
    my ($mpfd, $parentfd, $last_dir) = walk_tree_nofollow($rootdir, $mount, 1, $rootuid, $rootgid);
    return ($rootdir, $mount_path, $mpfd, $parentfd, $last_dir);
}

# use $rootdir = undef to just return the corresponding mount path
sub mountpoint_mount {
    my ($mountpoint, $rootdir, $storage_cfg, $snapname, $rootuid, $rootgid) = @_;
    return __mountpoint_mount($mountpoint, $rootdir, $storage_cfg, $snapname, $rootuid, $rootgid, undef);
}

sub mountpoint_stage {
    my ($mountpoint, $stage_dir, $storage_cfg, $snapname, $rootuid, $rootgid) = @_;
    my ($path, $loop, $dev) =
	__mountpoint_mount($mountpoint, $stage_dir, $storage_cfg, $snapname, $rootuid, $rootgid, 1);

    if (!defined($path)) {
	die "failed to mount subvolume: $!\n";
    }

    # We clone the mount point and leave it there in order to keep them connected to eg. loop
    # devices in case we're hotplugging (which would allow contaienrs to unmount the new mount
    # point).
    my $err;
    my $fd = PVE::Tools::open_tree(&AT_FDCWD, $stage_dir, &OPEN_TREE_CLOEXEC | &OPEN_TREE_CLONE)
	or die "open_tree() on mount point failed: $!\n";

    return wantarray ? ($path, $loop, $dev, $fd) : $fd;
}

sub mountpoint_insert_staged {
    my ($mount_fd, $rootdir_fd, $mp_dir, $opt, $rootuid, $rootgid) = @_;

    if (!defined($rootdir_fd)) {
	sysopen($rootdir_fd, '.', O_PATH | O_DIRECTORY)
	    or die "failed to open '.': $!\n";
    }

    my $dest_fd = walk_tree_nofollow_fd('/', $rootdir_fd, $mp_dir, 1, $rootuid, $rootgid);

    PVE::Tools::move_mount(
	fileno($mount_fd),
	'',
	fileno($dest_fd),
	'',
	&MOVE_MOUNT_F_EMPTY_PATH | &MOVE_MOUNT_T_EMPTY_PATH,
    ) or die "failed to move '$opt' into container hierarchy: $!\n";
}

# Use $stage_mount, $rootdir is treated as a temporary path to "stage" the file system. The user
#   can then open a file descriptor to it which can be used with the `move_mount` syscall.
sub __mountpoint_mount {
    my ($mountpoint, $rootdir, $storage_cfg, $snapname, $rootuid, $rootgid, $stage_mount) = @_;

    # When staging mount points we always mount to $rootdir directly (iow. as if `mp=/`).
    # This is required since __mount_prepare_rootdir() will return handles to the parent directory
    # which we use in __bindmount_verify()!
    my $mount = $stage_mount ? '/': $mountpoint->{mp};

    my $volid = $mountpoint->{volume};
    my $type = $mountpoint->{type};
    my $quota = !$snapname && !$mountpoint->{ro} && $mountpoint->{quota};
    my $mounted_dev;

    return if !$volid || !$mount;

    $mount =~ s!/+!/!g;

    my $mount_path;
    my ($mpfd, $parentfd, $last_dir);

    if (defined($rootdir)) {
	($rootdir, $mount_path, $mpfd, $parentfd, $last_dir) =
	    __mount_prepare_rootdir($rootdir, $mount, $rootuid, $rootgid);
    }

    if (defined($stage_mount)) {
	$mount_path = $rootdir;
    }

    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "unknown snapshot path for '$volid'" if !$storage && defined($snapname);

    my $optlist = [];

    if (my $mountopts = $mountpoint->{mountoptions}) {
	my @opts = split(/;/, $mountpoint->{mountoptions});
	push @$optlist, grep { PVE::LXC::Config::is_valid_mount_option($_) } @opts;
    }

    my $acl = $mountpoint->{acl};

    if ($acl) {
	push @$optlist, 'acl';
    } elsif (defined($acl)) {
	my $noacl = 1;

	if ($storage) {
	    my (undef, undef, undef, undef, undef, undef, $format) =
		PVE::Storage::parse_volname($storage_cfg, $volid);

	    $noacl = 0 if $format eq 'raw';
	}

	push @$optlist, 'noacl' if $noacl;
    }

    my $optstring = join(',', @$optlist);
    my $readonly = $mountpoint->{ro};

    my @extra_opts;
    @extra_opts = ('-o', $optstring) if $optstring;

    if ($storage) {

	my $scfg = PVE::Storage::storage_config($storage_cfg, $storage);

	PVE::Storage::activate_volumes($storage_cfg, [$volid], $snapname);
	my $path = PVE::Storage::map_volume($storage_cfg, $volid, $snapname);

	$path = PVE::Storage::path($storage_cfg, $volid, $snapname) if !defined($path);

	my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	    PVE::Storage::parse_volname($storage_cfg, $volid);

	$format = 'iso' if $vtype eq 'iso'; # allow to handle iso files

	if ($format eq 'subvol') {
	    if ($mount_path) {
		my (undef, $name) = PVE::Storage::parse_volname($storage_cfg, $volid);
		if (defined($snapname)) {
		    $name .= "\@$snapname";
		    if ($scfg->{type} eq 'zfspool') {
			PVE::Tools::run_command(['mount', '-o', 'ro', @extra_opts, '-t', 'zfs', "$scfg->{pool}/$name", $mount_path]);
		    } else {
			die "cannot mount subvol snapshots for storage type '$scfg->{type}'\n";
		    }
		} else {
		    if (defined($acl) && $scfg->{type} eq 'zfspool') {
			my $acltype = ($acl ? 'acltype=posixacl' : 'acltype=noacl');
			PVE::Tools::run_command(['zfs', 'set', $acltype, "$scfg->{pool}/$name"]);
		    }
		    bindmount($path, $parentfd, $last_dir//$rootdir, $mount_path, $readonly, @extra_opts);
		    warn "cannot enable quota control for bind mounted subvolumes\n" if $quota;
		}
	    }
	    return wantarray ? ($path, 0, undef) : $path;
	} elsif ($format eq 'raw' || $format eq 'iso') {
	    # NOTE: 'mount' performs canonicalization without the '-c' switch, which for
	    # device-mapper devices is special-cased to use the /dev/mapper symlinks.
	    # Our autodev hook expects the /dev/dm-* device currently
	    # and will create the /dev/mapper symlink accordingly
	    $path = Cwd::realpath($path);
	    die "failed to get device path\n" if !$path;
	    ($path) = ($path =~ /^(.*)$/s); #untaint
	    my $domount = sub {
		my ($path) = @_;
		if ($mount_path) {
		    if ($format eq 'iso') {
			PVE::Tools::run_command(['mount', '-o', 'ro', @extra_opts, $path, $mount_path]);
		    } elsif ($isBase || defined($snapname)) {
			PVE::Tools::run_command(['mount', '-o', 'ro,noload', @extra_opts, $path, $mount_path]);
		    } else {
			if ($quota) {
			    push @extra_opts, '-o', 'usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0';
			}
			push @extra_opts, '-o', 'ro' if $readonly;
			PVE::Tools::run_command(['mount', @extra_opts, $path, $mount_path]);
		    }
		}
	    };
	    my $use_loopdev = 0;
	    if ($scfg->{content}->{rootdir}) {
		if ($scfg->{path}) {
		    $mounted_dev = run_with_loopdev($domount, $path, $readonly);
		    $use_loopdev = 1;
		} else {
		    $mounted_dev = $path;
		    &$domount($path);
		}
	    } else {
		die "storage '$storage' does not support containers\n";
	    }
	    return wantarray ? ($path, $use_loopdev, $mounted_dev) : $path;
	} else {
	    die "unsupported image format '$format'\n";
	}
    } elsif ($type eq 'device') {
	push @extra_opts, '-o', 'ro' if $readonly;
	push @extra_opts, '-o', 'usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0' if $quota;
	# See the NOTE above about devicemapper canonicalization
	my ($devpath) = (Cwd::realpath($volid) =~ /^(.*)$/s); # realpath() taints
	PVE::Tools::run_command(['mount', @extra_opts, $volid, $mount_path]) if $mount_path;
	return wantarray ? ($volid, 0, $devpath) : $volid;
    } elsif ($type eq 'bind') {
	die "directory '$volid' does not exist\n" if ! -d $volid;
	bindmount($volid, $parentfd, $last_dir//$rootdir, $mount_path, $readonly, @extra_opts) if $mount_path;
	warn "cannot enable quota control for bind mounts\n" if $quota;
	return wantarray ? ($volid, 0, undef) : $volid;
    }

    die "unsupported storage";
}

sub mountpoint_hotplug :prototype($$$$$) {
    my ($vmid, $conf, $opt, $mp, $storage_cfg) = @_;

    my (undef, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);

    # We do the rest in a fork with an unshared mount namespace, because:
    #  -) change our papparmor profile to that of /usr/bin/lxc-start
    #  -) we're now going to 'stage' # the mountpoint, then grab it, then move into the
    #     container's namespace, then mount it.

    PVE::Tools::run_fork(sub {
	# Pin the container pid longer, we also need to get its monitor/parent:
	my ($ct_pid, $ct_pidfd) = open_lxc_pid($vmid)
	    or die "failed to open pidfd of container $vmid\'s init process\n";

	my ($monitor_pid, $monitor_pidfd) = open_ppid($ct_pid)
	    or die "failed to open pidfd of container $vmid\'s monitor process\n";

	my $ct_mnt_ns = $get_container_namespace->($vmid, $ct_pid, 'mnt');
	my $monitor_mnt_ns = $get_container_namespace->($vmid, $monitor_pid, 'mnt');

	# Grab a file descriptor to our apparmor label file so we can change into the 'lxc-start'
	# profile to lower our privileges to the same level we have in the start hook:
	sysopen(my $aa_fd, "/proc/self/attr/current", O_WRONLY)
	    or die "failed to open '/proc/self/attr/current' for writing: $!\n";
	# But switch namespaces first, to make sure the namespace switches aren't blocked by
	# apparmor.

	# Change into the monitor's mount namespace. We "pin" the mount into the monitor's
	# namespace for it to remain active there since the container will be able to unmount
	# hotplugged mount points and thereby potentially free up loop devices, which is a security
	# concern.
	PVE::Tools::setns(fileno($monitor_mnt_ns), PVE::Tools::CLONE_NEWNS);
	chdir('/')
	    or die "failed to change root directory within the monitor's mount namespace: $!\n";

	my $dir = get_staging_mount_path($opt);

	# Now switch our apparmor profile before mounting:
	my $data = 'changeprofile pve-container-mounthotplug';
	my $data_written = syswrite($aa_fd, $data, length($data));
	if (!defined($data_written) || $data_written != length($data)) {
	    die "failed to change apparmor profile: $!\n";
	}
	# Check errors on close as well:
	close($aa_fd)
	    or die "failed to change apparmor profile (close() failed): $!\n";

	my $mount_fd = mountpoint_stage($mp, $dir, $storage_cfg, undef, $rootuid, $rootgid);

	PVE::Tools::setns(fileno($ct_mnt_ns), PVE::Tools::CLONE_NEWNS);
	chdir('/')
	    or die "failed to change root directory within the container's mount namespace: $!\n";

	mountpoint_insert_staged($mount_fd, undef, $mp->{mp}, $opt, $rootuid, $rootgid);
    });
}

# Create a directory in the mountpoint staging tempfs.
sub get_staging_mount_path($) {
    my ($opt) = @_;

    my $target = get_staging_tempfs() . "/$opt";
    if (!mkdir($target) && $! != EEXIST) {
	die "failed to create directory $target: $!\n";
    }

    return $target;
}

# Mount tmpfs for mount point staging and return the path.
sub get_staging_tempfs() {
    # We choose a path in /var/lib/lxc/ here because the lxc-start apparmor profile restricts most
    # mounts to that.
    my $target = '/var/lib/lxc/.pve-staged-mounts';
    if (!mkdir($target)) {
	return $target if $! == EEXIST;
	die "failed to create directory $target: $!\n";
    }

    PVE::Tools::mount("none", $target, 'tmpfs', 0, "size=8k,mode=755")
	or die "failed to mount $target as tmpfs: $!\n";

    return $target;
}

sub mkfs {
    my ($dev, $rootuid, $rootgid) = @_;

    run_command(
	[
	    'mkfs.ext4',
	    '-O',
	    'mmp',
	    '-E',
	    "root_owner=$rootuid:$rootgid",
	    $dev,
	],
	outfunc => sub {
	    my $line = shift;
	    # a hack to print only the relevant stuff, i.e., the one which could help on repair
	    if ($line =~ /^(Creating filesystem|Filesystem UUID|Superblock backups|\s+\d+, \d)/) {
		print "$line\n";
	    }
	},
	errfunc => sub {
	    my $line = shift;
	    print STDERR "$line\n" if $line && $line !~ /^mke2fs \d\.\d/;
	}
    );
}

sub format_disk {
    my ($storage_cfg, $volid, $rootuid, $rootgid) = @_;

    if ($volid =~ m!^/dev/.+!) {
	mkfs($volid);
	return;
    }

    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "cannot format volume '$volid' with no storage\n" if !$storage;

    PVE::Storage::activate_volumes($storage_cfg, [$volid]);

    my $path = PVE::Storage::map_volume($storage_cfg, $volid);

    $path = PVE::Storage::path($storage_cfg, $volid) if !defined($path);

    my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	PVE::Storage::parse_volname($storage_cfg, $volid);

    die "cannot format volume '$volid' (format == $format)\n"
	if $format ne 'raw';

    mkfs($path, $rootuid, $rootgid);
}

sub destroy_disks {
    my ($storecfg, $vollist) = @_;

    foreach my $volid (@$vollist) {
	eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	warn $@ if $@;
    }
}

sub alloc_disk {
    my ($storecfg, $vmid, $storage, $size_kb, $rootuid, $rootgid) = @_;

    my $needs_chown = 0;
    my $volid;

    my $scfg = PVE::Storage::storage_config($storecfg, $storage);
    # fixme: use better naming ct-$vmid-disk-X.raw?

    eval {
	my $do_format = 0;
	if ($scfg->{content}->{rootdir} && $scfg->{path}) {
	    if ($size_kb > 0 && !($scfg->{type} eq 'btrfs' && $scfg->{quotas})) {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
		$do_format = 1;
	    } else {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol', undef, $size_kb);
		$needs_chown = 1;
	    }
	} elsif ($scfg->{type} eq 'zfspool') {
	    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol', undef, $size_kb);
	    $needs_chown = 1;
	} elsif ($scfg->{content}->{rootdir}) {
	    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
	    $do_format = 1;
	} else {
	    die "content type 'rootdir' is not available or configured on storage '$storage'\n";
	}
	format_disk($storecfg, $volid, $rootuid, $rootgid) if $do_format;
    };
    if (my $err = $@) {
	# in case formatting got interrupted:
	if (defined($volid)) {
	    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	    warn $@ if $@;
	}
	die $err;
    }

    return ($volid, $needs_chown);
}

sub create_disks {
    my ($storecfg, $vmid, $settings, $conf, $pending) = @_;

    my $vollist = [];

    eval {
	my (undef, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
	my $chown_vollist = [];

	PVE::LXC::Config->foreach_volume($settings, sub {
	    my ($ms, $mountpoint) = @_;

	    my $volid = $mountpoint->{volume};
	    my $mp = $mountpoint->{mp};

	    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	    if ($storage && ($volid =~ $NEW_DISK_RE)) {
		my ($storeid, $size_gb) = ($1, $2);

		my $size_kb = int(${size_gb}*1024) * 1024;

		my $needs_chown = 0;
		($volid, $needs_chown) = alloc_disk($storecfg, $vmid, $storage, $size_kb, $rootuid, $rootgid);
		push @$chown_vollist, $volid if $needs_chown;
		push @$vollist, $volid;
		$mountpoint->{volume} = $volid;
		$mountpoint->{size} = $size_kb * 1024;
		if ($pending) {
		    $conf->{pending}->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
		} else {
		    $conf->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
		}
	    } else {
		# use specified/existing volid/dir/device
		$conf->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
	    }
	});

	PVE::Storage::activate_volumes($storecfg, $chown_vollist, undef);
	foreach my $volid (@$chown_vollist) {
	    my $path = PVE::Storage::path($storecfg, $volid, undef);
	    chown($rootuid, $rootgid, $path);
	}
	PVE::Storage::deactivate_volumes($storecfg, $chown_vollist, undef);
    };
    # free allocated images on error
    if (my $err = $@) {
	destroy_disks($storecfg, $vollist);
	die $err;
    }
    return $vollist;
}

sub update_disksize {
    my ($vmid, $conf, $all_volumes) = @_;

    my $changes;
    my $prefix = "CT $vmid:";

    my $update_mp = sub {
	my ($key, $mp, @param) = @_;
	my $size = $all_volumes->{$mp->{volume}}->{size} // 0;

	if (!defined($mp->{size}) || $size != $mp->{size}) {
	    $changes = 1;
	    print "$prefix updated volume size of '$mp->{volume}' in config.\n";
	    $mp->{size} = $size;
	    my $no_mp = $key eq 'rootfs'; # rootfs is handled different from other mount points
	    $conf->{$key} = PVE::LXC::Config->print_ct_mountpoint($mp, $no_mp);
	}
    };

    PVE::LXC::Config->foreach_volume($conf, $update_mp);

    return $changes;
}

sub update_unused {
    my ($vmid, $conf, $all_volumes) = @_;

    my $changes;
    my $prefix = "CT $vmid:";

    # Note: it is allowed to define multiple storage entries with the same path
    # (alias), so we need to check both 'volid' and real 'path' (two different
    # volid can point to the same path).

    # used and unused disks
    my $refpath = {};
    my $orphans = {};

    foreach my $opt (keys %$conf) {
	next if ($opt !~ m/^unused\d+$/);
	my $vol = $all_volumes->{$conf->{$opt}};
	$refpath->{$vol->{path}} = $vol->{volid};
    }

    foreach my $key (keys %$all_volumes) {
	my $vol = $all_volumes->{$key};
	my $in_use = PVE::LXC::Config->is_volume_in_use($conf, $vol->{volid});
	my $path = $vol->{path};

	if ($in_use) {
	    $refpath->{$path} = $key;
	    delete $orphans->{$path};
	} else {
	    if ((!$orphans->{$path}) && (!$refpath->{$path})) {
	        $orphans->{$path} = $key;
	    }
	}
    }

    for my $key (keys %$orphans) {
	my $disk = $orphans->{$key};
	my $unused = PVE::LXC::Config->add_unused_volume($conf, $disk);

	if ($unused) {
	    $changes = 1;
	    print "$prefix add unreferenced volume '$disk' as '$unused' to config.\n";
	}
    }

    return $changes;
}

sub scan_volids {
    my ($cfg, $vmid) = @_;

    my $info = PVE::Storage::vdisk_list($cfg, undef, $vmid, undef, 'rootdir');

    my $all_volumes = {};
    foreach my $storeid (keys %$info) {
	foreach my $item (@{$info->{$storeid}}) {
	    my $volid = $item->{volid};
	    next if !($volid && $item->{size});
	    $item->{path} = PVE::Storage::path($cfg, $volid);
	    $all_volumes->{$volid} = $item;
	}
    }

    return $all_volumes;
}

sub rescan {
    my ($vmid, $nolock, $dryrun) = @_;

    my $cfg = PVE::Storage::config();

    print "rescan volumes...\n";
    my $all_volumes = scan_volids($cfg, $vmid);

    my $updatefn =  sub {
	my ($vmid) = @_;

	my $changes;
	my $conf = PVE::LXC::Config->load_config($vmid);

	PVE::LXC::Config->check_lock($conf);

	my $vm_volids = {};
	foreach my $volid (keys %$all_volumes) {
	    my $info = $all_volumes->{$volid};
	    $vm_volids->{$volid} = $info if $info->{vmid} == $vmid;
	}

	my $upu = update_unused($vmid, $conf, $vm_volids);
	my $upd = update_disksize($vmid, $conf, $vm_volids);
	$changes = $upu || $upd;

	PVE::LXC::Config->write_config($vmid, $conf) if $changes && !$dryrun;
    };

    if (defined($vmid)) {
	if ($nolock) {
	    &$updatefn($vmid);
	} else {
	    PVE::LXC::Config->lock_config($vmid, $updatefn, $vmid);
	}
    } else {
	my $vmlist = config_list();
	foreach my $vmid (keys %$vmlist) {
	    if ($nolock) {
		&$updatefn($vmid);
	    } else {
		PVE::LXC::Config->lock_config($vmid, $updatefn, $vmid);
	    }
	}
    }
}


# bash completion helper

sub complete_os_templates {
    my ($cmdname, $pname, $cvalue) = @_;

    my $cfg = PVE::Storage::config();

    my $storeid;

    if ($cvalue =~ m/^([^:]+):/) {
	$storeid = $1;
    }

    my $vtype = $cmdname eq 'restore' ? 'backup' : 'vztmpl';
    my $data = PVE::Storage::template_list($cfg, $storeid, $vtype);

    my $res = [];
    foreach my $id (keys %$data) {
	foreach my $item (@{$data->{$id}}) {
	    push @$res, $item->{volid} if defined($item->{volid});
	}
    }

    return $res;
}

my $complete_ctid_full = sub {
    my ($running) = @_;

    my $idlist = vmstatus();

    my $active_hash = list_active_containers();

    my $res = [];

    foreach my $id (keys %$idlist) {
	my $d = $idlist->{$id};
	if (defined($running)) {
	    next if $d->{template};
	    next if $running && !$active_hash->{$id};
	    next if !$running && $active_hash->{$id};
	}
	push @$res, $id;

    }
    return $res;
};

sub complete_ctid {
    return &$complete_ctid_full();
}

sub complete_ctid_stopped {
    return &$complete_ctid_full(0);
}

sub complete_ctid_running {
    return &$complete_ctid_full(1);
}

sub parse_id_maps {
    my ($conf) = @_;

    my $id_map = [];
    my $rootuid = 0;
    my $rootgid = 0;

    my $lxc = $conf->{lxc};
    foreach my $entry (@$lxc) {
	my ($key, $value) = @$entry;

	next if $key ne 'lxc.idmap';

	if ($value =~ /^([ug])\s+(\d+)\s+(\d+)\s+(\d+)\s*$/) {
	    my ($type, $ct, $host, $length) = ($1, $2, $3, $4);
	    push @$id_map, [$type, $ct, $host, $length];
	    if ($ct == 0) {
		$rootuid = $host if $type eq 'u';
		$rootgid = $host if $type eq 'g';
	    }
	} else {
	    die "failed to parse idmap: $value\n";
	}
    }

    if (!@$id_map && $conf->{unprivileged}) {
	# Should we read them from /etc/subuid?
	$id_map = [ ['u', '0', '100000', '65536'],
	            ['g', '0', '100000', '65536'] ];
	$rootuid = $rootgid = 100000;
    }

    return ($id_map, $rootuid, $rootgid);
}

sub validate_id_maps {
    my ($id_map) = @_;

    # $mappings->{$type}->{$side} = [ { line => $line, start => $start, count => $count }, ... ]
    #   $type: either "u" or "g"
    #   $side: either "container" or "host"
    #   $line: index of this mapping in @$id_map
    #   $start, $count: interval of this mapping
    my $mappings = { u => {}, g => {} };
    for (my $i = 0; $i < scalar(@$id_map); $i++) {
	my ($type, $ct_start, $host_start, $count) = $id_map->[$i]->@*;
	my $sides = $mappings->{$type};
	push $sides->{host}->@*, { line => $i, start => $host_start, count => $count };
	push $sides->{container}->@*, { line => $i, start => $ct_start, count => $count };
    }

    # find the first conflict between two consecutive mappings when sorted by their start id
    for my $type (qw(u g)) {
	for my $side (qw(container host)) {
	    my @entries = sort { $a->{start} <=> $b->{start} } $mappings->{$type}->{$side}->@*;
	    for my $idx (1..scalar(@entries) - 1) {
		my $previous = $entries[$idx - 1];
		my $current = $entries[$idx];
		if ($previous->{start} + $previous->{count} > $current->{start}) {
		    my $conflict = $current->{start};
		    my @previous_line = $id_map->[$previous->{line}]->@*;
		    my @current_line = $id_map->[$current->{line}]->@*;
		    die "invalid map entry '@current_line': $side ${type}id $conflict "
		       ."is also mapped by entry '@previous_line'\n";
		}
	    }
	}
    }
}

sub map_ct_id_to_host {
    my ($id, $id_map, $id_type) = @_;

    for my $mapping (@$id_map) {
	my ($type, $ct, $host, $length) = @$mapping;

	next if ($type ne $id_type);

	if ($id >= $ct && $id < ($ct + $length)) {
	    return $host - $ct + $id;
	}
    }

    return $id;
}

sub map_ct_uid_to_host {
    my ($uid, $id_map) = @_;

    return map_ct_id_to_host($uid, $id_map, 'u');
}

sub map_ct_gid_to_host {
    my ($gid, $id_map) = @_;

    return map_ct_id_to_host($gid, $id_map, 'g');
}

sub userns_command {
    my ($id_map) = @_;
    if (@$id_map) {
	return ['lxc-usernsexec', (map { ('-m', join(':', @$_)) } @$id_map), '--'];
    }
    return [];
}

my sub print_ct_stderr_log {
    my ($vmid) = @_;
    my $log = eval { file_get_contents("/run/pve/ct-$vmid.stderr") };
    return if !$log;

    while ($log =~ /^\h*(lxc-start:?\s+$vmid:?\s*\S+\s*)?(.*?)\h*$/gm) {
	my $line = $2;
	print STDERR "$line\n";
    }
}
my sub print_ct_warn_log {
    my ($vmid) = @_;
    my $log_fn = "/run/pve/ct-$vmid.warnings";
    my $log = eval { file_get_contents($log_fn) };
    return if !$log;

    while ($log =~ /^\h*\s*(.*?)\h*$/gm) {
	PVE::RESTEnvironment::log_warn($1);
    }
    unlink $log_fn or warn "could not unlink '$log_fn' - $!\n";
}

my sub monitor_state_change($$) {
    my ($monitor_socket, $vmid) = @_;
    die "no monitor socket\n" if !defined($monitor_socket);

    while (1) {
	my ($type, $name, $value) = PVE::LXC::Monitor::read_lxc_message($monitor_socket);

	die "monitor socket: got EOF\n" if !defined($type);

	next if $name ne "$vmid" || $type ne 'STATE';

	if ($value eq PVE::LXC::Monitor::STATE_STARTING) {
	    alarm(0); # don't timeout after seeing the starting state
	} elsif ($value eq PVE::LXC::Monitor::STATE_ABORTING ||
		 $value eq PVE::LXC::Monitor::STATE_STOPPING ||
		 $value eq PVE::LXC::Monitor::STATE_STOPPED) {
	    return 0;
	} elsif ($value eq PVE::LXC::Monitor::STATE_RUNNING) {
	    return 1;
	} else {
	    warn "unexpected message from monitor socket - " .
		 "type: '$type' - value: '$value'\n";
	}
    }
}
my sub monitor_start($$) {
    my ($monitor_socket, $vmid) = @_;

    my $success = eval {
	PVE::Tools::run_with_timeout(10, \&monitor_state_change, $monitor_socket, $vmid)
    };
    if (my $err = $@) {
	warn "problem with monitor socket, but continuing anyway: $err\n";
    } elsif (!$success) {
	print_ct_stderr_log($vmid);
	die "startup for container '$vmid' failed\n";
    }
}

sub vm_start {
    my ($vmid, $conf, $skiplock, $debug) = @_;

    # apply pending changes while starting
    if (scalar(keys %{$conf->{pending}})) {
	my $storecfg = PVE::Storage::config();
	PVE::LXC::Config->vmconfig_apply_pending($vmid, $conf, $storecfg);
	PVE::LXC::Config->write_config($vmid, $conf);
	$conf = PVE::LXC::Config->load_config($vmid); # update/reload
    }

    update_lxc_config($vmid, $conf);

    eval {
	my ($id_map, undef, undef) = PVE::LXC::parse_id_maps($conf);
	PVE::LXC::validate_id_maps($id_map);
    };
    warn "lxc.idmap: $@" if $@;

    my $skiplock_flag_fn = "/run/lxc/skiplock-$vmid";

    if ($skiplock) {
	open(my $fh, '>', $skiplock_flag_fn) || die "failed to open $skiplock_flag_fn for writing: $!\n";
	close($fh);
    }

    my $storage_cfg = PVE::Storage::config();
    my $vollist = PVE::LXC::Config->get_vm_volumes($conf);

    PVE::Storage::activate_volumes($storage_cfg, $vollist);

    my $monitor_socket = eval { PVE::LXC::Monitor::get_monitor_socket() };
    warn $@ if $@;

    unlink "/run/pve/ct-$vmid.stderr"; # systemd does not truncate log files

    my $is_debug = $debug || (!defined($debug) && $conf->{debug});
    my $base_unit = $is_debug ? 'pve-container-debug' : 'pve-container';

    my $cmd = ['systemctl', 'start', "$base_unit\@$vmid"];

    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'pre-start', 1);
    eval {
	run_command($cmd);

	monitor_start($monitor_socket, $vmid) if defined($monitor_socket);

	# if debug is requested, print the log it also when the start succeeded
	print_ct_stderr_log($vmid) if $is_debug;

	print_ct_warn_log($vmid); # always print warn log, if any
    };
    if (my $err = $@) {
	unlink $skiplock_flag_fn;
	die $err;
    }
    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'post-start');

    return;
}

# Helper to stop a container completely and make sure it has stopped completely.
# This is necessary because we want the post-stop hook to have completed its
# unmount-all step, but post-stop happens after lxc puts the container into the
# STOPPED state.
# $kill - if true it will always do an immediate hard-stop
# $shutdown_timeout - the timeout to wait for a gracefull shutdown
# $kill_after_timeout - if true, send a hardstop if shutdown timed out
sub vm_stop {
    my ($vmid, $kill, $shutdown_timeout, $kill_after_timeout) = @_;

    # Open the container's command socket.
    my $path = "\0/var/lib/lxc/$vmid/command";
    my $sock = IO::Socket::UNIX->new(
	Type => SOCK_STREAM(),
	Peer => $path,
    );
    if (!$sock) {
	return if $! == ECONNREFUSED; # The container is not running
	die "failed to open container ${vmid}'s command socket: $!\n";
    }

    my $conf = PVE::LXC::Config->load_config($vmid);
    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'pre-stop');

    # Stop the container:

    my $cmd = ['lxc-stop', '-n', $vmid];

    if ($kill) {
	push @$cmd, '--kill'; # doesn't allow timeouts
    } else {
	# lxc-stop uses a default timeout
	push @$cmd, '--nokill' if !$kill_after_timeout;

	if (defined($shutdown_timeout)) {
	    push @$cmd, '--timeout', $shutdown_timeout;
	    # Give run_command 5 extra seconds
	    $shutdown_timeout += 5;
	}
    }

    eval { run_command($cmd, timeout => $shutdown_timeout) };

    # Wait until the command socket is closed.
    # In case the lxc-stop call failed, reading from the command socket may block forever,
    # so poll with another timeout to avoid freezing the shutdown task.
    if (my $err = $@) {
	warn $err if $err;

	my $poll = IO::Poll->new();
	$poll->mask($sock => POLLIN | POLLHUP); # watch for input and EOF events
	$poll->poll($shutdown_timeout); # IO::Poll timeout is in seconds
	return if ($poll->events($sock) & POLLHUP);
    } else {
	my $result = <$sock>;
	return if !defined $result; # monitor is gone and the ct has stopped.
    }

    die "container did not stop\n";
}

sub vm_reboot {
    my ($vmid, $timeout, $skiplock) = @_;

    PVE::LXC::Config->lock_config($vmid, sub {
	return if !check_running($vmid);

	vm_stop($vmid, 0, $timeout, 1); # kill if timeout exceeds

	my $conf = PVE::LXC::Config->load_config($vmid);
	vm_start($vmid, $conf);
    });
}

sub run_unshared {
    my ($code) = @_;

    return PVE::Tools::run_fork(sub {
	# Unshare the mount namespace
	die "failed to unshare mount namespace: $!\n"
	    if !PVE::Tools::unshare(PVE::Tools::CLONE_NEWNS);
	run_command(['mount', '--make-rslave', '/']);
	return $code->();
    });
}

my $copy_volume = sub {
    my ($src_volid, $src, $dst_volid, $dest, $storage_cfg, $snapname, $bwlimit, $rootuid,  $rootgid) = @_;

    my $src_mp = { volume => $src_volid, mp => '/', ro => 1 };
    $src_mp->{type} = PVE::LXC::Config->classify_mountpoint($src_volid);

    my $dst_mp = { volume => $dst_volid, mp => '/', ro => 0 };
    $dst_mp->{type} = PVE::LXC::Config->classify_mountpoint($dst_volid);

    my @mounted;
    eval {
	# mount and copy
	mkdir $src;
	mountpoint_mount($src_mp, $src, $storage_cfg, $snapname, $rootuid, $rootgid);
	push @mounted, $src;
	mkdir $dest;
	mountpoint_mount($dst_mp, $dest, $storage_cfg, undef, $rootuid, $rootgid);
	push @mounted, $dest;

	$bwlimit //= 0;

	run_command([
	    'rsync',
	    '--stats',
	    '-X',
	    '-A',
	    '--numeric-ids',
	    '-aH',
	    '--whole-file',
	    '--sparse',
	    '--one-file-system',
	    "--bwlimit=$bwlimit",
	    "$src/",
	    $dest
	]);
    };
    my $err = $@;

    # Wait for rsync's children to release dest so that
    # consequent file operations (umount, remove) are possible
    while ((system {"fuser"} "fuser",  "-s", $dest) == 0) {sleep 1};

    foreach my $mount (reverse @mounted) {
	eval { run_command(['/bin/umount', $mount], errfunc => sub{})};
	warn "Can't umount $mount\n" if $@;
    }

    # If this fails they're used as mount points in a concurrent operation
    # (which should not happen but there's also no real need to get rid of them).
    rmdir $dest;
    rmdir $src;

    die $err if $err;
};

# Should not be called after unsharing the mount namespace!
sub copy_volume {
    my ($mp, $vmid, $storage, $storage_cfg, $conf, $snapname, $bwlimit) = @_;

    die "cannot copy volumes of type $mp->{type}\n" if $mp->{type} ne 'volume';
    File::Path::make_path("/var/lib/lxc/$vmid");
    my $dest = "/var/lib/lxc/$vmid/.copy-volume-1";
    my $src  = "/var/lib/lxc/$vmid/.copy-volume-2";

    # get id's for unprivileged container
    my (undef, $rootuid, $rootgid) = parse_id_maps($conf);

    # Allocate the disk before unsharing in order to make sure zfs subvolumes
    # are visible in this namespace, otherwise the host only sees the empty
    # (not-mounted) directory.
    my $new_volid;
    eval {
	# Make sure $mp contains a correct size.
	$mp->{size} = PVE::Storage::volume_size_info($storage_cfg, $mp->{volume});
	my $needs_chown;
	($new_volid, $needs_chown) = alloc_disk($storage_cfg, $vmid, $storage, $mp->{size}/1024, $rootuid, $rootgid);
	if ($needs_chown) {
	    PVE::Storage::activate_volumes($storage_cfg, [$new_volid], undef);
	    my $path = PVE::Storage::path($storage_cfg, $new_volid, undef);
	    chown($rootuid, $rootgid, $path);
	}

	run_unshared(sub {
	    $copy_volume->($mp->{volume}, $src, $new_volid, $dest, $storage_cfg, $snapname, $bwlimit, $rootuid, $rootgid);
	});
    };
    if (my $err = $@) {
	PVE::Storage::vdisk_free($storage_cfg, $new_volid)
	    if defined($new_volid);
	die $err;
    }

    return $new_volid;
}

sub get_lxc_version() {
    my $version;
    run_command([qw(lxc-start --version)], outfunc => sub {
	my ($line) = @_;
	# We only parse out major & minor version numbers.
	if ($line =~ /^(\d+)\.(\d+)(?:\D.*)?$/) {
	    $version = [$1, $2];
	}
    });

    die "failed to get lxc version\n" if !defined($version);

    # return as a list:
    return $version->@*;
}

sub freeze($) {
    my ($vmid) = @_;
    if (PVE::CGroup::cgroup_mode() == 2) {
	PVE::LXC::Command::freeze($vmid, 30);
    } else {
	PVE::LXC::CGroup->new($vmid)->freeze_thaw(1);
    }
}

sub thaw($) {
    my ($vmid) = @_;
    if (PVE::CGroup::cgroup_mode() == 2) {
	PVE::LXC::Command::unfreeze($vmid, 30);
    } else {
	PVE::LXC::CGroup->new($vmid)->freeze_thaw(0);
    }
}

sub create_ifaces_ipams_ips {
    my ($conf, $vmid) = @_;

    return if !$have_sdn;

    for my $opt (keys %$conf) {
	next if $opt !~ m/^net(\d+)$/;
	my $net = PVE::LXC::Config->parse_lxc_network($conf->{$opt});
	next if $net->{type} ne 'veth';
	PVE::Network::SDN::Vnets::add_next_free_cidr($net->{bridge}, $conf->{hostname}, $net->{hwaddr}, $vmid, undef, 1);
    }
}

sub delete_ifaces_ipams_ips {
    my ($conf, $vmid) = @_;

    return if !$have_sdn;

    for my $opt (keys %$conf) {
	next if $opt !~ m/^net(\d+)$/;
	my $net = PVE::LXC::Config->parse_lxc_network($conf->{$opt});
	eval { PVE::Network::SDN::Vnets::del_ips_from_mac($net->{bridge}, $net->{hwaddr}, $conf->{hostname}) };
	warn $@ if $@;
    }
}

1;
