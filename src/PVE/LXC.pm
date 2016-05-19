package PVE::LXC;

use strict;
use warnings;

use POSIX qw(EINTR);

use Socket;

use File::Path;
use File::Spec;
use Cwd qw();
use Fcntl qw(O_RDONLY);

use PVE::Exception qw(raise_perm_exc);
use PVE::Storage;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Tools qw($IPV6RE $IPV4RE dir_glob_foreach lock_file lock_file_full);
use PVE::Network;
use PVE::AccessControl;
use PVE::ProcFSTools;
use PVE::LXC::Config;
use Time::HiRes qw (gettimeofday);

use Data::Dumper;

my $nodename = PVE::INotify::nodename();

my $cpuinfo= PVE::ProcFSTools::read_cpuinfo();

our $COMMON_TAR_FLAGS = [ '--sparse', '--numeric-owner', '--acls',
                          '--xattrs',
                          '--xattrs-include=user.*',
                          '--xattrs-include=security.capability',
                          '--warning=no-xattr-write' ];

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
	$res->{$vmid}->{type} = 'lxc';
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
    my ($vmid) = @_;

    my $raw = read_cgroup_value('cpuacct', $vmid, 'cpuacct.stat', 1);

    my $stat = {};

    if ($raw =~ m/^user (\d+)\nsystem (\d+)\n/) {

	$stat->{utime} = $1;
	$stat->{stime} = $2;

    }

    return $stat;
};

sub vmstatus {
    my ($opt_vmid) = @_;

    my $list = $opt_vmid ? { $opt_vmid => { type => 'lxc' }} : config_list();

    my $active_hash = list_active_containers();

    my $cpucount = $cpuinfo->{cpus} || 1;

    my $cdtime = gettimeofday;

    my $uptime = (PVE::ProcFSTools::read_proc_uptime(1))[0];

    foreach my $vmid (keys %$list) {
	my $d = $list->{$vmid};

	eval { $d->{pid} = find_lxc_pid($vmid) if defined($active_hash->{$vmid}); };
	warn $@ if $@; # ignore errors (consider them stopped)

	$d->{status} = $d->{pid} ? 'running' : 'stopped';

	my $cfspath = PVE::LXC::Config->cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	$d->{name} = $conf->{'hostname'} || "CT$vmid";
	$d->{name} =~ s/[\s]//g;

	$d->{cpus} = $conf->{cpulimit} || $cpucount;

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

	my $ctime = (stat("/proc/$pid"))[10]; # 10 = ctime
	$d->{uptime} = time - $ctime; # the method lxcfs uses

	$d->{mem} = read_cgroup_value('memory', $vmid, 'memory.usage_in_bytes');
	$d->{swap} = read_cgroup_value('memory', $vmid, 'memory.memsw.usage_in_bytes') - $d->{mem};

	my $blkio_bytes = read_cgroup_value('blkio', $vmid, 'blkio.throttle.io_service_bytes', 1);
	my @bytes = split(/\n/, $blkio_bytes);
	foreach my $byte (@bytes) {
	    if (my ($key, $value) = $byte =~ /(Read|Write)\s+(\d+)/) {
		$d->{diskread} = $2 if $key eq 'Read';
		$d->{diskwrite} = $2 if $key eq 'Write';
	    }
	}

	my $pstat = &$parse_cpuacct_stat($vmid);

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

sub read_cgroup_value {
    my ($group, $vmid, $name, $full) = @_;

    my $path = "/sys/fs/cgroup/$group/lxc/$vmid/$name";

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


sub update_lxc_config {
    my ($storage_cfg, $vmid, $conf) = @_;

    my $dir = "/var/lib/lxc/$vmid";

    if ($conf->{template}) {

	unlink "$dir/config";

	return;
    }

    my $raw = '';

    die "missing 'arch' - internal error" if !$conf->{arch};
    $raw .= "lxc.arch = $conf->{arch}\n";

    my $unprivileged = $conf->{unprivileged};
    my $custom_idmap = grep { $_->[0] eq 'lxc.id_map' } @{$conf->{lxc}};

    my $ostype = $conf->{ostype} || die "missing 'ostype' - internal error";
    if ($ostype =~ /^(?:debian | ubuntu | centos | fedora | opensuse | archlinux | alpine | gentoo | unmanaged)$/x) {
	my $inc ="/usr/share/lxc/config/$ostype.common.conf";
	$inc ="/usr/share/lxc/config/common.conf" if !-f $inc;
	$raw .= "lxc.include = $inc\n";
	if ($unprivileged || $custom_idmap) {
	    $inc = "/usr/share/lxc/config/$ostype.userns.conf";
	    $inc = "/usr/share/lxc/config/userns.conf" if !-f $inc;
	    $raw .= "lxc.include = $inc\n"
	}
    } else {
	die "implement me (ostype $ostype)";
    }

    # WARNING: DO NOT REMOVE this without making sure that loop device nodes
    # cannot be exposed to the container with r/w access (cgroup perms).
    # When this is enabled mounts will still remain in the monitor's namespace
    # after the container unmounted them and thus will not detach from their
    # files while the container is running!
    $raw .= "lxc.monitor.unshare = 1\n";

    # Should we read them from /etc/subuid?
    if ($unprivileged && !$custom_idmap) {
	$raw .= "lxc.id_map = u 0 100000 65536\n";
	$raw .= "lxc.id_map = g 0 100000 65536\n";
    }

    if (!PVE::LXC::Config->has_dev_console($conf)) {
	$raw .= "lxc.console = none\n";
	$raw .= "lxc.cgroup.devices.deny = c 5:1 rwm\n";
    }

    my $ttycount = PVE::LXC::Config->get_tty_count($conf);
    $raw .= "lxc.tty = $ttycount\n";

    # some init scripts expect a linux terminal (turnkey).
    $raw .= "lxc.environment = TERM=linux\n";
    
    my $utsname = $conf->{hostname} || "CT$vmid";
    $raw .= "lxc.utsname = $utsname\n";

    my $memory = $conf->{memory} || 512;
    my $swap = $conf->{swap} // 0;

    my $lxcmem = int($memory*1024*1024);
    $raw .= "lxc.cgroup.memory.limit_in_bytes = $lxcmem\n";

    my $lxcswap = int(($memory + $swap)*1024*1024);
    $raw .= "lxc.cgroup.memory.memsw.limit_in_bytes = $lxcswap\n";

    if (my $cpulimit = $conf->{cpulimit}) {
	$raw .= "lxc.cgroup.cpu.cfs_period_us = 100000\n";
	my $value = int(100000*$cpulimit);
	$raw .= "lxc.cgroup.cpu.cfs_quota_us = $value\n";
    }

    my $shares = $conf->{cpuunits} || 1024;
    $raw .= "lxc.cgroup.cpu.shares = $shares\n";

    die "missing 'rootfs' configuration\n"
	if !defined($conf->{rootfs});

    my $mountpoint = PVE::LXC::Config->parse_ct_rootfs($conf->{rootfs});

    $raw .= "lxc.rootfs = $dir/rootfs\n";

    my $netcount = 0;
    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $ind = $1;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	$netcount++;
	$raw .= "lxc.network.type = veth\n";
	$raw .= "lxc.network.veth.pair = veth${vmid}i${ind}\n";
	$raw .= "lxc.network.hwaddr = $d->{hwaddr}\n" if defined($d->{hwaddr});
	$raw .= "lxc.network.name = $d->{name}\n" if defined($d->{name});
	$raw .= "lxc.network.mtu = $d->{mtu}\n" if defined($d->{mtu});
    }

    if (my $lxcconf = $conf->{lxc}) {
	foreach my $entry (@$lxcconf) {
	    my ($k, $v) = @$entry;
	    $netcount++ if $k eq 'lxc.network.type';
	    $raw .= "$k = $v\n";
	}
    }

    $raw .= "lxc.network.type = empty\n" if !$netcount;
    
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
    my ($vmid, $conf) = @_;

    my $cmode = PVE::LXC::Config->get_cmode($conf);

    if ($cmode eq 'console') {
	return ['lxc-console', '-n',  $vmid, '-t', 0];
    } elsif ($cmode eq 'tty') {
	return ['lxc-console', '-n',  $vmid];
    } elsif ($cmode eq 'shell') {
	return ['lxc-attach', '--clear-env', '-n', $vmid];
    } else {
	die "internal error";
    }
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
    my ($storage_cfg, $vmid, $conf) = @_;

    PVE::LXC::Config->foreach_mountpoint($conf, sub {
	my ($ms, $mountpoint) = @_;
	delete_mountpoint_volume($storage_cfg, $vmid, $mountpoint->{volume});
    });

    rmdir "/var/lib/lxc/$vmid/rootfs";
    unlink "/var/lib/lxc/$vmid/config";
    rmdir "/var/lib/lxc/$vmid";
    destroy_config($vmid);

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

    my $rootinfo = PVE::LXC::Config->parse_ct_rootfs($conf->{rootfs});
    my $volid = $rootinfo->{volume};

    die "Template feature is not available for '$volid'\n"
	if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);

    PVE::Storage::activate_volumes($storecfg, [$volid]);

    my $template_volid = PVE::Storage::vdisk_create_base($storecfg, $volid);
    $rootinfo->{volume} = $template_volid;
    $conf->{rootfs} = PVE::LXC::Config->print_ct_mountpoint($rootinfo, 1);

    PVE::LXC::Config->write_config($vmid, $conf);
}

sub check_ct_modify_config_perm {
    my ($rpcenv, $authuser, $vmid, $pool, $newconf, $delete) = @_;

    return 1 if $authuser eq 'root@pam';

    my $check = sub {
	my ($opt, $delete) = @_;
	if ($opt eq 'cpus' || $opt eq 'cpuunits' || $opt eq 'cpulimit') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'rootfs' || $opt =~ /^mp\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	    return if $delete;
	    my $data = $opt eq 'rootfs' ? PVE::LXC::Config->parse_ct_rootfs($newconf->{$opt})
					: PVE::LXC::Config->parse_ct_mountpoint($newconf->{$opt});
	    raise_perm_exc("mountpoint type $data->{type}") if $data->{type} ne 'volume';
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
    my ($vmid, $storage_cfg, $conf) = @_;

    my $rootdir = "/var/lib/lxc/$vmid/rootfs";
    File::Path::make_path($rootdir);

    my $volid_list = PVE::LXC::Config->get_vm_volumes($conf);
    PVE::Storage::activate_volumes($storage_cfg, $volid_list);

    eval {
	PVE::LXC::Config->foreach_mountpoint($conf, sub {
	    my ($ms, $mountpoint) = @_;

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

my $check_mount_path = sub {
    my ($path) = @_;
    $path = File::Spec->canonpath($path);
    my $real = Cwd::realpath($path);
    if ($real ne $path) {
	die "mount path modified by symlink: $path != $real";
    }
};

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

sub bindmount {
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

# use $rootdir = undef to just return the corresponding mount path
sub mountpoint_mount {
    my ($mountpoint, $rootdir, $storage_cfg, $snapname) = @_;

    my $volid = $mountpoint->{volume};
    my $mount = $mountpoint->{mp};
    my $type = $mountpoint->{type};
    my $quota = !$snapname && !$mountpoint->{ro} && $mountpoint->{quota};
    my $mounted_dev;
    
    return if !$volid || !$mount;

    my $mount_path;
    
    if (defined($rootdir)) {
	$rootdir =~ s!/+$!!;
	$mount_path = "$rootdir/$mount";
	$mount_path =~ s!/+!/!g;
	&$check_mount_path($mount_path);
	File::Path::mkpath($mount_path);
    }
    
    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

    die "unknown snapshot path for '$volid'" if !$storage && defined($snapname);

    my $optstring = '';
    my $acl = $mountpoint->{acl};
    if (defined($acl)) {
	$optstring .= ($acl ? 'acl' : 'noacl');
    }
    my $readonly = $mountpoint->{ro};

    my @extra_opts = ('-o', $optstring) if $optstring;

    if ($storage) {

	my $scfg = PVE::Storage::storage_config($storage_cfg, $storage);
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
		    bindmount($path, $mount_path, $readonly, @extra_opts);
		    warn "cannot enable quota control for bind mounted subvolumes\n" if $quota;
		}
	    }
	    return wantarray ? ($path, 0, undef) : $path;
	} elsif ($format eq 'raw' || $format eq 'iso') {
	    # NOTE: 'mount' performs canonicalization without the '-c' switch, which for
	    # device-mapper devices is special-cased to use the /dev/mapper symlinks.
	    # Our autodev hook expects the /dev/dm-* device currently
	    # and will create the /dev/mapper symlink accordingly
	    ($path) = (Cwd::realpath($path) =~ /^(.*)$/s); # realpath() taints
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
	&$check_mount_path($volid);
	bindmount($volid, $mount_path, $readonly, @extra_opts) if $mount_path;
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

	    if ($storage && ($volid =~ m/^([^:\s]+):(\d+(\.\d+)?)$/)) {
		my ($storeid, $size_gb) = ($1, $2);

		my $size_kb = int(${size_gb}*1024) * 1024;

		my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		# fixme: use better naming ct-$vmid-disk-X.raw?

		if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
		    if ($size_kb > 0) {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw',
							   undef, $size_kb);
			format_disk($storecfg, $volid, $rootuid, $rootgid);
		    } else {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
							   undef, 0);
			push @$chown_vollist, $volid;
		    }
		} elsif ($scfg->{type} eq 'zfspool') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
					               undef, $size_kb);
		    push @$chown_vollist, $volid;
		} elsif ($scfg->{type} eq 'drbd' || $scfg->{type} eq 'lvm' || $scfg->{type} eq 'lvmthin') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
		    format_disk($storecfg, $volid, $rootuid, $rootgid);

		} elsif ($scfg->{type} eq 'rbd') {

		    die "krbd option must be enabled on storage type '$scfg->{type}'\n" if !$scfg->{krbd};
		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size_kb);
		    format_disk($storecfg, $volid, $rootuid, $rootgid);
		} else {
		    die "unable to create containers on storage type '$scfg->{type}'\n";
		}
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
	next if $key ne 'lxc.id_map';
	if ($value =~ /^([ug])\s+(\d+)\s+(\d+)\s+(\d+)\s*$/) {
	    my ($type, $ct, $host, $length) = ($1, $2, $3, $4);
	    push @$id_map, [$type, $ct, $host, $length];
	    if ($ct == 0) {
		$rootuid = $host if $type eq 'u';
		$rootgid = $host if $type eq 'g';
	    }
	} else {
	    die "failed to parse id_map: $value\n";
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


1;
