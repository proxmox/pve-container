package PVE::LXC;

use strict;
use warnings;

use POSIX qw(EINTR);

use Socket;

use File::Path;
use File::Spec;
use Cwd qw();
use Fcntl qw(O_RDONLY O_NOFOLLOW O_DIRECTORY);
use Errno qw(ELOOP ENOTDIR EROFS ECONNREFUSED);
use IO::Socket::UNIX;

use PVE::Exception qw(raise_perm_exc);
use PVE::Storage;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw($IPV6RE $IPV4RE dir_glob_foreach lock_file lock_file_full O_PATH);
use PVE::CpuSet;
use PVE::Network;
use PVE::AccessControl;
use PVE::ProcFSTools;
use PVE::Syscall;
use PVE::LXC::Config;

use Time::HiRes qw (gettimeofday);

my $nodename = PVE::INotify::nodename();

my $cpuinfo= PVE::ProcFSTools::read_cpuinfo();

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
	$res->{$vmid} = { type => 'lxc', vmid => $vmid };
    }
    return $res;
}

sub destroy_config {
    my ($vmid) = @_;

    unlink PVE::LXC::Config->config_file($vmid, $nodename);
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

my $parse_cpuacct_stat = sub {
    my ($vmid, $unprivileged) = @_;

    my $raw = read_cgroup_value('cpuacct', $vmid, $unprivileged, 'cpuacct.stat', 1);

    my $stat = {};

    if ($raw =~ m/^user (\d+)\nsystem (\d+)\n/) {

	$stat->{utime} = $1;
	$stat->{stime} = $2;

    }

    return $stat;
};

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
};

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc', vmid => $opt_vmid }} : config_list();

    my $active_hash = list_active_containers();

    my $cpucount = $cpuinfo->{cpus} || 1;

    my $cdtime = gettimeofday;

    my $uptime = (PVE::ProcFSTools::read_proc_uptime(1))[0];
    my $clock_ticks = POSIX::sysconf(&POSIX::_SC_CLK_TCK);

    my $unprivileged = {};

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};

	eval { $d->{pid} = find_lxc_pid($vmid) if defined($active_hash->{$vmid}); };
	warn $@ if $@; # ignore errors (consider them stopped)

	$d->{status} = $d->{pid} ? 'running' : 'stopped';

	my $cfspath = PVE::LXC::Config->cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	$unprivileged->{$vmid} = $conf->{unprivileged};

	$d->{name} = $conf->{'hostname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;

	$d->{cpus} = $conf->{cores} || $conf->{cpulimit};
	$d->{cpus} = $cpucount if !$d->{cpus};

	$d->{lock} = $conf->{lock} || '';

	if ($d->{pid}) {
	    my $res = get_container_disk_usage($vmid, $d->{pid});
	    $d->{disk} = $res->{used};
	    $d->{maxdisk} = $res->{total};
	} else {
	    $d->{disk} = 0;
	    # use 4GB by default ??
	    if (my $rootfs = $conf->{rootfs}) {
		my $rootinfo = PVE::LXC::Config->parse_ct_rootfs($rootfs);
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

	$d->{template} = PVE::LXC::Config->is_template($conf);
    }

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};
	my $pid = $d->{pid};

	next if !$pid; # skip stopped CTs

	my $proc_pid_stat = PVE::ProcFSTools::read_proc_pid_stat($pid);
	$d->{uptime} = int(($uptime - $proc_pid_stat->{starttime}) / $clock_ticks); # the method lxcfs uses

	my $unpriv = $unprivileged->{$vmid};

	if (-d '/sys/fs/cgroup/memory') {
	    my $memory_stat = read_cgroup_list('memory', $vmid, $unpriv, 'memory.stat');
	    my $mem_usage_in_bytes = read_cgroup_value('memory', $vmid, $unpriv, 'memory.usage_in_bytes');

	    $d->{mem} = $mem_usage_in_bytes - $memory_stat->{total_cache};
	    $d->{swap} = read_cgroup_value('memory', $vmid, $unpriv, 'memory.memsw.usage_in_bytes') - $mem_usage_in_bytes;
	} else {
	    $d->{mem} = 0;
	    $d->{swap} = 0;
	}

	if (-d '/sys/fs/cgroup/blkio') {
	    my $blkio_bytes = read_cgroup_value('blkio', $vmid, $unpriv, 'blkio.throttle.io_service_bytes', 1);
	    my @bytes = split(/\n/, $blkio_bytes);
	    foreach my $byte (@bytes) {
		if (my ($key, $value) = $byte =~ /(Read|Write)\s+(\d+)/) {
		    $d->{diskread} += $2 if $key eq 'Read';
		    $d->{diskwrite} += $2 if $key eq 'Write';
		}
	    }
	} else {
	    $d->{diskread} = 0;
	    $d->{diskwrite} = 0;
	}

	if (-d '/sys/fs/cgroup/cpuacct') {
	    my $pstat = $parse_cpuacct_stat->($vmid, $unpriv);

	    my $used = $pstat->{utime} + $pstat->{stime};

	    my $old = $last_proc_vmid_stat->{$vmid};
	    if (!$old) {
		$last_proc_vmid_stat->{$vmid} = {
		    time => $cdtime,
		    used => $used,
		    cpu => 0,
		};
		next;
	    }

	    my $dtime = ($cdtime -  $old->{time}) * $cpucount * $cpuinfo->{user_hz};

	    if ($dtime > 1000) {
		my $dutime = $used -  $old->{used};

		$d->{cpu} = (($dutime/$dtime)* $cpucount) / $d->{cpus};
		$last_proc_vmid_stat->{$vmid} = {
		    time => $cdtime,
		    used => $used,
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

sub read_cgroup_list($$$$) {
    my ($group, $vmid, $unprivileged, $name) = @_;

    my $content = read_cgroup_value($group, $vmid, $unprivileged, $name, 1);

    return { split(/\s+/, $content) };
}

sub read_cgroup_value($$$$$) {
    my ($group, $vmid, $unprivileged, $name, $full) = @_;

    my $nsdir = $unprivileged ? '' : 'ns/';
    my $path = "/sys/fs/cgroup/$group/lxc/$vmid/${nsdir}$name";

    return PVE::Tools::file_get_contents($path) if $full;

    return PVE::Tools::file_read_firstline($path);
}

sub write_cgroup_value {
   my ($group, $vmid, $name, $value) = @_;

   my $path = "/sys/fs/cgroup/$group/lxc/$vmid/$name";
   PVE::ProcFSTools::write_proc_entry($path, $value) if -e $path;

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

sub get_cgroup_subsystems {
	my $v1 = {};
	my $v2 = 0;
	my $data = PVE::Tools::file_get_contents('/proc/self/cgroup');
	while ($data =~ /^\d+:([^:\n]*):.*$/gm) {
		my $type = $1;
		if (length($type)) {
			$v1->{$_} = 1 foreach split(/,/, $type);
		} else {
			$v2 = 1;
		}
	}
	return wantarray ? ($v1, $v2) : $v1;
}

sub update_lxc_config {
    my ($vmid, $conf) = @_;

    my $dir = "/var/lib/lxc/$vmid";

    if ($conf->{template}) {

	unlink "$dir/config";

	return;
    }

    my $raw = '';

    die "missing 'arch' - internal error" if !$conf->{arch};
    $raw .= "lxc.arch = $conf->{arch}\n";

    my $unprivileged = $conf->{unprivileged};
    my $custom_idmap = grep { $_->[0] eq 'lxc.idmap' } @{$conf->{lxc}};

    my $ostype = $conf->{ostype} || die "missing 'ostype' - internal error";

    my $cfgpath = '/usr/share/lxc/config';
    my $inc = "$cfgpath/$ostype.common.conf";
    $inc ="$cfgpath/common.conf" if !-f $inc;
    $raw .= "lxc.include = $inc\n";
    if ($unprivileged || $custom_idmap) {
	$inc = "$cfgpath/$ostype.userns.conf";
	$inc = "$cfgpath/userns.conf" if !-f $inc;
	$raw .= "lxc.include = $inc\n";
	$raw .= "lxc.seccomp.profile = $cfgpath/pve-userns.seccomp\n";
    }

    # WARNING: DO NOT REMOVE this without making sure that loop device nodes
    # cannot be exposed to the container with r/w access (cgroup perms).
    # When this is enabled mounts will still remain in the monitor's namespace
    # after the container unmounted them and thus will not detach from their
    # files while the container is running!
    $raw .= "lxc.monitor.unshare = 1\n";

    my $cgv1 = get_cgroup_subsystems();

    # Should we read them from /etc/subuid?
    if ($unprivileged && !$custom_idmap) {
	$raw .= "lxc.idmap = u 0 100000 65536\n";
	$raw .= "lxc.idmap = g 0 100000 65536\n";
    }

    if (!PVE::LXC::Config->has_dev_console($conf)) {
	$raw .= "lxc.console.path = none\n";
	$raw .= "lxc.cgroup.devices.deny = c 5:1 rwm\n" if $cgv1->{devices};
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
    }

    if ($cgv1->{cpu}) {
	if (my $cpulimit = $conf->{cpulimit}) {
	    $raw .= "lxc.cgroup.cpu.cfs_period_us = 100000\n";
	    my $value = int(100000*$cpulimit);
	    $raw .= "lxc.cgroup.cpu.cfs_quota_us = $value\n";
	}

	my $shares = $conf->{cpuunits} || 1024;
	$raw .= "lxc.cgroup.cpu.shares = $shares\n";
    }

    die "missing 'rootfs' configuration\n"
	if !defined($conf->{rootfs});

    my $mountpoint = PVE::LXC::Config->parse_ct_rootfs($conf->{rootfs});

    $raw .= "lxc.rootfs.path = $dir/rootfs\n";

    foreach my $k (sort keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	$raw .= "lxc.net.$ind.type = veth\n";
	$raw .= "lxc.net.$ind.veth.pair = veth${vmid}i${ind}\n";
	$raw .= "lxc.net.$ind.hwaddr = $d->{hwaddr}\n" if defined($d->{hwaddr});
	$raw .= "lxc.net.$ind.name = $d->{name}\n" if defined($d->{name});
	$raw .= "lxc.net.$ind.mtu = $d->{mtu}\n" if defined($d->{mtu});
    }

    if ($cgv1->{cpuset}) {
	my $had_cpuset = 0;
	if (my $lxcconf = $conf->{lxc}) {
	    foreach my $entry (@$lxcconf) {
		my ($k, $v) = @$entry;
		$had_cpuset = 1 if $k eq 'lxc.cgroup.cpuset.cpus';
		$raw .= "$k = $v\n";
	    }
	}

	my $cores = $conf->{cores};
	if (!$had_cpuset && $cores) {
	    my $cpuset = eval { PVE::CpuSet->new_from_cgroup('lxc', 'effective_cpus') };
	    $cpuset = PVE::CpuSet->new_from_cgroup('', 'effective_cpus') if !$cpuset;
	    my @members = $cpuset->members();
	    while (scalar(@members) > $cores) {
		my $randidx = int(rand(scalar(@members)));
		$cpuset->delete($members[$randidx]);
		splice(@members, $randidx, 1); # keep track of the changes
	    }
	    $raw .= "lxc.cgroup.cpuset.cpus = ".$cpuset->short_string()."\n";
	}
    }

    File::Path::mkpath("$dir/rootfs");

    PVE::Tools::file_set_contents("$dir/config", $raw);
}

# verify and cleanup nameserver list (replace \0 with ' ')
sub verify_nameserver_list {
    my ($nameserver_list) = @_;

    my @list = ();
    foreach my $server (PVE::Tools::split_list($nameserver_list)) {
	PVE::JSONSchema::pve_verify_ip($server);
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
    my ($vmid, $conf, $noescapechar) = @_;

    my $cmode = PVE::LXC::Config->get_cmode($conf);

    my $cmd = [];
    if ($cmode eq 'console') {
	push @$cmd, 'lxc-console', '-n',  $vmid, '-t', 0;
	push @$cmd, '-e', -1 if $noescapechar;
    } elsif ($cmode eq 'tty') {
	push @$cmd, 'lxc-console', '-n',  $vmid;
	push @$cmd, '-e', -1 if $noescapechar;
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
    PVE::Storage::vdisk_free($storage_cfg, $volume) if $vmid == $owner;
}

sub destroy_lxc_container {
    my ($storage_cfg, $vmid, $conf, $replacement_conf) = @_;

    PVE::LXC::Config->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;
	delete_mountpoint_volume($storage_cfg, $vmid, $mountpoint->{volume});
    });

    rmdir "/var/lib/lxc/$vmid/rootfs";
    unlink "/var/lib/lxc/$vmid/config";
    rmdir "/var/lib/lxc/$vmid";
    if (defined $replacement_conf) {
	PVE::LXC::Config->write_config($vmid, $replacement_conf);
    } else {
	destroy_config($vmid);
    }

    #my $cmd = ['lxc-destroy', '-n', $vmid ];
    #PVE::Tools::run_command($cmd);
}

sub vm_stop_cleanup {
    my ($storage_cfg, $vmid, $conf, $keepActive) = @_;
    
    eval {
	if (!$keepActive) {

            my $vollist = PVE::LXC::Config->get_vm_volumes($conf);
	    PVE::Storage::deactivate_volumes($storage_cfg, $vollist);
	}
    };
    warn $@ if $@; # avoid errors - just warn
}

my $safe_num_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a != $b;
};

my $safe_string_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a ne $b;
};

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

	if (&$safe_string_ne($oldnet->{hwaddr}, $newnet->{hwaddr}) ||
	    &$safe_string_ne($oldnet->{name}, $newnet->{name})) {

	    PVE::Network::veth_delete($veth);
	    delete $conf->{$opt};
	    PVE::LXC::Config->write_config($vmid, $conf);

	    hotplug_net($vmid, $conf, $opt, $newnet, $netid);

	} else {
	    if (&$safe_string_ne($oldnet->{bridge}, $newnet->{bridge}) ||
		&$safe_num_ne($oldnet->{tag}, $newnet->{tag}) ||
		&$safe_num_ne($oldnet->{firewall}, $newnet->{firewall})) {

		if ($oldnet->{bridge}) {
		    PVE::Network::tap_unplug($veth);
		    foreach (qw(bridge tag firewall)) {
			delete $oldnet->{$_};
		    }
		    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($oldnet);
		    PVE::LXC::Config->write_config($vmid, $conf);
		}

		PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall}, $newnet->{trunks}, $newnet->{rate});
		# This includes the rate:
		foreach (qw(bridge tag firewall rate)) {
		    $oldnet->{$_} = $newnet->{$_} if $newnet->{$_};
		}
	    } elsif (&$safe_string_ne($oldnet->{rate}, $newnet->{rate})) {
		# Rate can be applied on its own but any change above needs to
		# include the rate in tap_plug since OVS resets everything.
		PVE::Network::tap_rate_limit($veth, $newnet->{rate});
		$oldnet->{rate} = $newnet->{rate}
	    }
	    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($oldnet);
	    PVE::LXC::Config->write_config($vmid, $conf);
	}
    } else {
	hotplug_net($vmid, $conf, $opt, $newnet, $netid);
    }

    update_ipconfig($vmid, $conf, $opt, $eth, $newnet, $rootdir);
}

sub hotplug_net {
    my ($vmid, $conf, $opt, $newnet, $netid) = @_;

    my $veth = "veth${vmid}i${netid}";
    my $vethpeer = $veth . "p";
    my $eth = $newnet->{name};

    PVE::Network::veth_create($veth, $vethpeer, $newnet->{bridge}, $newnet->{hwaddr});
    PVE::Network::tap_plug($veth, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall}, $newnet->{trunks}, $newnet->{rate});

    # attach peer in container
    my $cmd = ['lxc-device', '-n', $vmid, 'add', $vethpeer, "$eth" ];
    PVE::Tools::run_command($cmd);

    # link up peer in container
    $cmd = ['lxc-attach', '-n', $vmid, '-s', 'NETWORK', '--', '/sbin/ip', 'link', 'set', $eth ,'up'  ];
    PVE::Tools::run_command($cmd);

    my $done = { type => 'veth' };
    foreach (qw(bridge tag firewall hwaddr name)) {
	$done->{$_} = $newnet->{$_} if $newnet->{$_};
    }
    $conf->{$opt} = PVE::LXC::Config->print_lxc_network($done);

    PVE::LXC::Config->write_config($vmid, $conf);
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

	my $change_ip = &$safe_string_ne($oldip, $newip);
	my $change_gw = &$safe_string_ne($optdata->{$gw}, $newgw);

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

my $enter_namespace = sub {
    my ($vmid, $pid, $which, $type) = @_;
    sysopen my $fd, "/proc/$pid/ns/$which", O_RDONLY
	or die "failed to open $which namespace of container $vmid: $!\n";
    PVE::Tools::setns(fileno($fd), $type)
	or die "failed to enter $which namespace of container $vmid: $!\n";
    close $fd;
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

    # Now sync all mountpoints...
    my $mounts = PVE::ProcFSTools::parse_mounts($mountdata);
    foreach my $mp (@$mounts) {
	my ($what, $dir, $fs) = @$mp;
	next if $fs eq 'fuse.lxcfs';
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

    PVE::LXC::Config->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;

	my $volid = $mountpoint->{volume};

	die "Template feature is not available for '$volid'\n"
	    if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);
    });

    PVE::LXC::Config->foreach_mountpoint($conf, sub {
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
    my ($rpcenv, $authuser, $vmid, $pool, $newconf, $delete) = @_;

    return 1 if $authuser eq 'root@pam';

    my $check = sub {
	my ($opt, $delete) = @_;
	if ($opt eq 'cores' || $opt eq 'cpuunits' || $opt eq 'cpulimit') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'rootfs' || $opt =~ /^mp\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	    return if $delete;
	    my $data = $opt eq 'rootfs' ? PVE::LXC::Config->parse_ct_rootfs($newconf->{$opt})
					: PVE::LXC::Config->parse_ct_mountpoint($newconf->{$opt});
	    raise_perm_exc("mount point type $data->{type} is only allowed for root\@pam")
		if $data->{type} ne 'volume';
	} elsif ($opt eq 'memory' || $opt eq 'swap') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt =~ m/^net\d+$/ || $opt eq 'nameserver' ||
		 $opt eq 'searchdomain' || $opt eq 'hostname') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
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

sub umount_all {
    my ($vmid, $storage_cfg, $conf, $noerr) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    my $volid_list = PVE::LXC::Config->get_vm_volumes($conf);

    PVE::LXC::Config->foreach_mountpoint_reverse($conf, sub {
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
		warn $err;
	    } else {
		die $err;
	    }
	}
    });
}

sub mount_all {
    my ($vmid, $storage_cfg, $conf, $ignore_ro) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    File::Path::make_path($rootdir);

    my $volid_list = PVE::LXC::Config->get_vm_volumes($conf);
    PVE::Storage::activate_volumes($storage_cfg, $volid_list);

    eval {
	PVE::LXC::Config->foreach_mountpoint($conf, sub {
	    my ($ms, $mountpoint) = @_;

	    $mountpoint->{ro} = 0 if $ignore_ro;

	    mountpoint_mount($mountpoint, $rootdir, $storage_cfg);
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
    my ($func, $file) = @_;
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
    PVE::Tools::run_command(['losetup', '--show', '-f', $file], outfunc => $parser);
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
sub walk_tree_nofollow($$$) {
    my ($start, $subdir, $mkdir) = @_;

    # splitdir() returns '' for empty components including the leading /
    my @comps = grep { length($_)>0 } File::Spec->splitdir($subdir);

    sysopen(my $fd, $start, O_PATH | O_DIRECTORY)
	or die "failed to open start directory $start: $!\n";

    my $dir = $start;
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
	}

	close $second if defined($last_component);
	$last_component = $component;
	$second = $fd;
	$fd = $next;
    }

    return ($fd, defined($last_component) && $second, $last_component) if wantarray;
    close $second if defined($last_component);
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
    my ($rootdir, $mount) = @_;
    $rootdir =~ s!/+!/!g;
    $rootdir =~ s!/+$!!;
    my $mount_path = "$rootdir/$mount";
    my ($mpfd, $parentfd, $last_dir) = walk_tree_nofollow($rootdir, $mount, 1);
    return ($rootdir, $mount_path, $mpfd, $parentfd, $last_dir);
}

# use $rootdir = undef to just return the corresponding mount path
sub mountpoint_mount {
    my ($mountpoint, $rootdir, $storage_cfg, $snapname) = @_;

    my $volid = $mountpoint->{volume};
    my $mount = $mountpoint->{mp};
    my $type = $mountpoint->{type};
    my $quota = !$snapname && !$mountpoint->{ro} && $mountpoint->{quota};
    my $mounted_dev;
    
    return if !$volid || !$mount;

    $mount =~ s!/+!/!g;

    my $mount_path;
    my ($mpfd, $parentfd, $last_dir);
    
    if (defined($rootdir)) {
	($rootdir, $mount_path, $mpfd, $parentfd, $last_dir) =
	    __mount_prepare_rootdir($rootdir, $mount);
    }
    
    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "unknown snapshot path for '$volid'" if !$storage && defined($snapname);

    my $optstring = '';
    my $acl = $mountpoint->{acl};
    if (defined($acl)) {
	$optstring .= ($acl ? 'acl' : 'noacl');
    }
    my $readonly = $mountpoint->{ro};

    my @extra_opts;
    @extra_opts = ('-o', $optstring) if $optstring;

    if ($storage) {

	my $scfg = PVE::Storage::storage_config($storage_cfg, $storage);

	# early sanity checks:
	# we otherwise call realpath on the rbd url
	die "containers on rbd storage without krbd are not supported\n"
	    if $scfg->{type} eq 'rbd' && !$scfg->{krbd};

	my $path = PVE::Storage::path($storage_cfg, $volid, $snapname);

	my ($vtype, undef, undef, undef, undef, $isBase, $format) =
	    PVE::Storage::parse_volname($storage_cfg, $volid);

	$format = 'iso' if $vtype eq 'iso'; # allow to handle iso files

	if ($format eq 'subvol') {
	    if ($mount_path) {
		if ($snapname) {
		    if ($scfg->{type} eq 'zfspool') {
			my $path_arg = $path;
			$path_arg =~ s!^/+!!;
			PVE::Tools::run_command(['mount', '-o', 'ro', @extra_opts, '-t', 'zfs', $path_arg, $mount_path]);
		    } else {
			die "cannot mount subvol snapshots for storage type '$scfg->{type}'\n";
		    }
		} else {
		    if (defined($acl) && $scfg->{type} eq 'zfspool') {
			my $acltype = ($acl ? 'acltype=posixacl' : 'acltype=noacl');
			my (undef, $name) = PVE::Storage::parse_volname($storage_cfg, $volid);
			$name .= "\@$snapname" if defined($snapname);
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
	    if ($scfg->{path}) {
		$mounted_dev = run_with_loopdev($domount, $path);
		$use_loopdev = 1;
	    } elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'lvm' ||
		     $scfg->{type} eq 'rbd' || $scfg->{type} eq 'lvmthin') {
		$mounted_dev = $path;
		&$domount($path);
	    } else {
		die "unsupported storage type '$scfg->{type}'\n";
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

sub mkfs {
    my ($dev, $rootuid, $rootgid) = @_;

    PVE::Tools::run_command(['mkfs.ext4', '-O', 'mmp',
			     '-E', "root_owner=$rootuid:$rootgid",
			     $dev]);
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

    my $path = PVE::Storage::path($storage_cfg, $volid);

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
	if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs' || $scfg->{type} eq 'cifs' ) {
	    if ($size_kb > 0) {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw',
						   undef, $size_kb);
		$do_format = 1;
	    } else {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
						   undef, 0);
		$needs_chown = 1;
	    }
	} elsif ($scfg->{type} eq 'zfspool') {

	    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
					       undef, $size_kb);
	    $needs_chown = 1;
	} elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'lvm' || $scfg->{type} eq 'lvmthin') {

	    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
	    $do_format = 1;

	} elsif ($scfg->{type} eq 'rbd') {

	    die "krbd option must be enabled on storage type '$scfg->{type}'\n" if !$scfg->{krbd};
	    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
	    $do_format = 1;
	} else {
	    die "unable to create containers on storage type '$scfg->{type}'\n";
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

our $NEW_DISK_RE = qr/^([^:\s]+):(\d+(\.\d+)?)$/;
sub create_disks {
    my ($storecfg, $vmid, $settings, $conf) = @_;

    my $vollist = [];

    eval {
	my (undef, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
	my $chown_vollist = [];

	PVE::LXC::Config->foreach_mountpoint($settings, sub {
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
		$conf->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
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
	# FIXME: remove the 'id_map' variant when lxc-3.0 arrives
	next if $key ne 'lxc.idmap' && $key ne 'lxc.id_map';
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

sub userns_command {
    my ($id_map) = @_;
    if (@$id_map) {
	return ['lxc-usernsexec', (map { ('-m', join(':', @$_)) } @$id_map), '--'];
    }
    return [];
}

sub vm_start {
    my ($vmid, $conf, $skiplock) = @_;

    update_lxc_config($vmid, $conf);

    my $skiplock_flag_fn = "/run/lxc/skiplock-$vmid";

    if ($skiplock) {
	open(my $fh, '>', $skiplock_flag_fn) || die "failed to open $skiplock_flag_fn for writing: $!\n";
	close($fh);
    }

    my $cmd = ['systemctl', 'start', "pve-container\@$vmid"];

    eval { PVE::Tools::run_command($cmd); };
    if (my $err = $@) {
	unlink $skiplock_flag_fn;
	die $err;
    }

    return;
}

# Helper to stop a container completely and make sure it has stopped completely.
# This is necessary because we want the post-stop hook to have completed its
# unmount-all step, but post-stop happens after lxc puts the container into the
# STOPPED state.
sub vm_stop {
    my ($vmid, $kill, $shutdown_timeout, $exit_timeout) = @_;

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

    # Stop the container:

    my $cmd = ['lxc-stop', '-n', $vmid];

    if ($kill) {
	push @$cmd, '--kill'; # doesn't allow timeouts
    } elsif (defined($shutdown_timeout)) {
	push @$cmd, '--timeout', $shutdown_timeout;
	# Give run_command 5 extra seconds
	$shutdown_timeout += 5;
    }

    eval { PVE::Tools::run_command($cmd, timeout => $shutdown_timeout) };
    if (my $err = $@) {
	warn $@ if $@;
    }

    my $result = 1;
    my $wait = sub { $result = <$sock>; };
    if (defined($exit_timeout)) {
	PVE::Tools::run_with_timeout($exit_timeout, $wait);
    } else {
	$wait->();
    }

    return if !defined $result; # monitor is gone and the ct has stopped.
    die "container did not stop\n";
}

sub run_unshared {
    my ($code) = @_;

    return PVE::Tools::run_fork(sub {
	# Unshare the mount namespace
	die "failed to unshare mount namespace: $!\n"
	    if !PVE::Tools::unshare(PVE::Tools::CLONE_NEWNS);
	PVE::Tools::run_command(['mount', '--make-rslave', '/']);
	return $code->();
    });
}

my $copy_volume = sub {
    my ($src_volid, $src, $dst_volid, $dest, $storage_cfg, $snapname) = @_;

    my $src_mp = { volume => $src_volid, mp => '/' };
    $src_mp->{type} = PVE::LXC::Config->classify_mountpoint($src_volid);

    my $dst_mp = { volume => $dst_volid, mp => '/' };
    $dst_mp->{type} = PVE::LXC::Config->classify_mountpoint($dst_volid);

    my @mounted;
    eval {
	# mount and copy
	mkdir $src;
	mountpoint_mount($src_mp, $src, $storage_cfg, $snapname);
	push @mounted, $src;
	mkdir $dest;
	mountpoint_mount($dst_mp, $dest, $storage_cfg);
	push @mounted, $dest;

	PVE::Tools::run_command(['/usr/bin/rsync', '--stats', '-X', '-A', '--numeric-ids',
				 '-aH', '--whole-file', '--sparse', '--one-file-system',
				 "$src/", $dest]);
    };
    my $err = $@;
    foreach my $mount (reverse @mounted) {
	eval { PVE::Tools::run_command(['/bin/umount', '--lazy', $mount], errfunc => sub{})};
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
    my ($mp, $vmid, $storage, $storage_cfg, $conf, $snapname) = @_;

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
	    $copy_volume->($mp->{volume}, $src, $new_volid, $dest, $storage_cfg, $snapname);
	});
    };
    if (my $err = $@) {
	PVE::Storage::vdisk_free($storage_cfg, $new_volid)
	    if defined($new_volid);
	die $err;
    }

    return $new_volid;
}

1;
