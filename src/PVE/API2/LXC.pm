package PVE::API2::LXC;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param run_command);
use PVE::Exception qw(raise raise_param_exc);
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::AccessControl;
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::LXC;
use PVE::LXCCreate;
use PVE::HA::Config;
use PVE::JSONSchema qw(get_standard_option);
use base qw(PVE::RESTHandler);

use Data::Dumper; # fixme: remove

my $get_container_storage = sub {
    my ($stcfg, $vmid, $pct_conf) = @_;

    my $rootinfo = PVE::LXC::parse_ct_mountpoint($pct_conf->{rootfs});
    my ($sid, $volname) = PVE::Storage::parse_volume_id($rootinfo->{volume});
    return wantarray ? ($sid, $volname) : $sid;
};

my $check_ct_modify_config_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $key_list) = @_;

    return 1 if $authuser ne 'root@pam';

    foreach my $opt (@$key_list) {

	if ($opt eq 'cpus' || $opt eq 'cpuunits' || $opt eq 'cpulimit') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'disk') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	} elsif ($opt eq 'memory' || $opt eq 'swap') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt =~ m/^net\d+$/ || $opt eq 'nameserver' ||
		 $opt eq 'searchdomain' || $opt eq 'hostname') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} else {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Options']);
	}
    }

    return 1;
};

my $alloc_rootfs = sub {
    my ($storage_conf, $storage, $disk_size_gb, $vmid) = @_;

    my $volid;

    my $size = 4*1024*1024; # defaults to 4G

    $size = int($disk_size_gb*1024) * 1024 if defined($disk_size_gb);

    eval {
	my $scfg = PVE::Storage::storage_config($storage_conf, $storage);
	# fixme: use better naming ct-$vmid-disk-X.raw?

	if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
	    if ($size > 0) {
		$volid = PVE::Storage::vdisk_alloc($storage_conf, $storage, $vmid, 'raw',
						   "vm-$vmid-rootfs.raw", $size);
	    } else {
		$volid = PVE::Storage::vdisk_alloc($storage_conf, $storage, $vmid, 'subvol',
						   "subvol-$vmid-rootfs", 0);
	    }
	} elsif ($scfg->{type} eq 'zfspool') {

	    $volid = PVE::Storage::vdisk_alloc($storage_conf, $storage, $vmid, 'subvol',
					       "subvol-$vmid-rootfs", $size);
	} else {
	    die "unable to create containers on storage type '$scfg->{type}'\n";
	}
    };
    if (my $err = $@) {
	# cleanup
	eval { PVE::Storage::vdisk_free($storage_conf, $volid) if $volid; };
	warn $@ if $@;
	die $err;
    }

    return $volid;
};

PVE::JSONSchema::register_standard_option('pve-lxc-snapshot-name', {
    description => "The name of the snapshot.",
    type => 'string', format => 'pve-configid',
    maxLength => 40,
});

__PACKAGE__->register_method({
    name => 'vmlist',
    path => '',
    method => 'GET',
    description => "LXC container index (per node).",
    permissions => {
	description => "Only list CTs where you have VM.Audit permissons on /vms/<vmid>.",
	user => 'all',
    },
    proxyto => 'node',
    protected => 1, # /proc files are only readable by root
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{vmid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $vmstatus = PVE::LXC::vmstatus();

	my $res = [];
	foreach my $vmid (keys %$vmstatus) {
	    next if !$rpcenv->check($authuser, "/vms/$vmid", [ 'VM.Audit' ], 1);

	    my $data = $vmstatus->{$vmid};
	    $data->{vmid} = $vmid;
	    push @$res, $data;
	}

	return $res;

    }});

__PACKAGE__->register_method({
    name => 'create_vm',
    path => '',
    method => 'POST',
    description => "Create or restore a container.",
    permissions => {
	user => 'all', # check inside
 	description => "You need 'VM.Allocate' permissions on /vms/{vmid} or on the VM pool /pool/{pool}. " .
	    "For restore, it is enough if the user has 'VM.Backup' permission and the VM already exists. " .
	    "You also need 'Datastore.AllocateSpace' permissions on the storage.",
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => PVE::LXC::json_config_properties_no_rootfs({
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    ostemplate => {
		description => "The OS template or backup file.",
		type => 'string',
		maxLength => 255,
	    },
	    password => {
		optional => 1,
		type => 'string',
		description => "Sets root password inside container.",
		minLength => 5,
	    },
	    storage => get_standard_option('pve-storage-id', {
		description => "Target storage.",
		default => 'local',
		optional => 1,
	    }),
	    size => {
		optional => 1,
		type => 'number',
		description => "Amount of disk space for the VM in GB. A zero indicates no limits.",
		minimum => 0,
		default => 4,
	    },
	    force => {
		optional => 1,
		type => 'boolean',
		description => "Allow to overwrite existing container.",
	    },
	    restore => {
		optional => 1,
		type => 'boolean',
		description => "Mark this as restore task.",
	    },
	    pool => {
		optional => 1,
		type => 'string', format => 'pve-poolid',
		description => "Add the VM to the specified pool.",
	    },
	}),
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $basecfg_fn = PVE::LXC::config_file($vmid);

	my $same_container_exists = -f $basecfg_fn;

	my $restore = extract_param($param, 'restore');

	if ($restore) {
	    # fixme: limit allowed parameters

	}
	
	my $force = extract_param($param, 'force');

	if (!($same_container_exists && $restore && $force)) {
	    PVE::Cluster::check_vmid_unused($vmid);
	}

	my $password = extract_param($param, 'password');

	my $disksize = extract_param($param, 'size');

	my $storage = extract_param($param, 'storage') // 'local';
	
	my $storage_cfg = cfs_read_file("storage.cfg");

	my $scfg = PVE::Storage::storage_check_node($storage_cfg, $storage, $node);

	raise_param_exc({ storage => "storage '$storage' does not support container root directories"})
	    if !$scfg->{content}->{rootdir};

	my $pool = extract_param($param, 'pool');

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	    $rpcenv->check_perm_modify($authuser, "/pool/$pool");
	}

	$rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace']);
	
	if ($rpcenv->check($authuser, "/vms/$vmid", ['VM.Allocate'], 1)) {
	    # OK
	} elsif ($pool && $rpcenv->check($authuser, "/pool/$pool", ['VM.Allocate'], 1)) {
	    # OK
	} elsif ($restore && $force && $same_container_exists &&
		 $rpcenv->check($authuser, "/vms/$vmid", ['VM.Backup'], 1)) {
	    # OK: user has VM.Backup permissions, and want to restore an existing VM
	} else {
	    raise_perm_exc();
	}

	&$check_ct_modify_config_perm($rpcenv, $authuser, $vmid, $pool, [ keys %$param]);

	PVE::Storage::activate_storage($storage_cfg, $storage);

	my $ostemplate = extract_param($param, 'ostemplate');

	my $archive;

	if ($ostemplate eq '-') {
	    die "pipe requires cli environment\n" 
		if $rpcenv->{type} ne 'cli'; 
	    die "pipe can only be used with restore tasks\n" 
		if !$restore;
	    die "pipe requires --size parameter\n" 
		if !defined($disksize);
	    $archive = '-';
	} else {
	    $rpcenv->check_volume_access($authuser, $storage_cfg, $vmid, $ostemplate);
	    $archive = PVE::Storage::abs_filesystem_path($storage_cfg, $ostemplate);
	}

	my $conf = {};

	PVE::LXC::update_pct_config($vmid, $conf, 0, $param);

	my $check_vmid_usage = sub {
	    if ($force) {
		die "cant overwrite running container\n"
		    if PVE::LXC::check_running($vmid);
	    } else {
		PVE::Cluster::check_vmid_unused($vmid);
	    }
	};

	my $code = sub {
	    &$check_vmid_usage(); # final check after locking

	    PVE::Cluster::check_cfs_quorum();

	    my $volid;

	    eval {
		if (!defined($disksize)) {
		    if ($restore) {
			my (undef, $disksize) = PVE::LXCCreate::recover_config($archive);
			die "unable to detect disk size - please specify with --size\n"
			    if !$disksize;
		    } else {
			$disksize = 4;
		    }
		}
		$volid = &$alloc_rootfs($storage_cfg, $storage, $disksize, $vmid);

		PVE::LXCCreate::create_rootfs($storage_cfg, $storage, $volid, $vmid, $conf,
					      $archive, $password, $restore);

		$conf->{rootfs} = "$volid,size=$disksize";

		# set some defaults
		$conf->{hostname} ||= "CT$vmid";
		$conf->{memory} ||= 512;
		$conf->{swap} //= 512;

		PVE::LXC::create_config($vmid, $conf);
	    };
	    if (my $err = $@) {
		eval { PVE::Storage::vdisk_free($storage_cfg, $volid) if $volid; };
		warn $@ if $@;
		PVE::LXC::destroy_config($vmid);
		die $err;
	    }
	};

	my $realcmd = sub { PVE::LXC::lock_container($vmid, 1, $code); };

	&$check_vmid_usage(); # first check before locking

	return $rpcenv->fork_worker($restore ? 'vzrestore' : 'vzcreate',
				    $vmid, $authuser, $realcmd);

    }});

my $vm_config_perm_list = [
	    'VM.Config.Disk',
	    'VM.Config.CPU',
	    'VM.Config.Memory',
	    'VM.Config.Network',
	    'VM.Config.Options',
    ];

__PACKAGE__->register_method({
    name => 'update_vm',
    path => '{vmid}/config',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set container options.",
    permissions => {
	check => ['perm', '/vms/{vmid}', $vm_config_perm_list, any => 1],
    },
    parameters => {
    	additionalProperties => 0,
	properties => PVE::LXC::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
		delete => {
		    type => 'string', format => 'pve-configid-list',
		    description => "A list of settings you want to delete.",
		    optional => 1,
		},
		digest => {
		    type => 'string',
		    description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		    maxLength => 40,
		    optional => 1,
		}
	    }),
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $digest = extract_param($param, 'digest');

	die "no options specified\n" if !scalar(keys %$param);

	my $delete_str = extract_param($param, 'delete');
	my @delete = PVE::Tools::split_list($delete_str);

	&$check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, [@delete]);

	foreach my $opt (@delete) {
	    raise_param_exc({ delete => "you can't use '-$opt' and " .
				  "-delete $opt' at the same time" })
		if defined($param->{$opt});

	    if (!PVE::LXC::option_exists($opt)) {
		raise_param_exc({ delete => "unknown option '$opt'" });
	    }
	}

	&$check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, [keys %$param]);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $code = sub {

	    my $conf = PVE::LXC::load_config($vmid);
	    PVE::LXC::check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    my $running = PVE::LXC::check_running($vmid);

	    PVE::LXC::update_pct_config($vmid, $conf, $running, $param, \@delete);

	    PVE::LXC::write_config($vmid, $conf);
	    PVE::LXC::update_lxc_config($storage_cfg, $vmid, $conf);
	};

	PVE::LXC::lock_container($vmid, undef, $code);

	return undef;
    }});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::CT",
    path => '{vmid}/firewall',
});

__PACKAGE__->register_method({
    name => 'vmdiridx',
    path => '{vmid}',
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
    permissions => {
	user => 'all',
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::LXC::load_config($param->{vmid});

	my $res = [
	    { subdir => 'config' },
	    { subdir => 'status' },
	    { subdir => 'vncproxy' },
	    { subdir => 'vncwebsocket' },
	    { subdir => 'spiceproxy' },
	    { subdir => 'migrate' },
#	    { subdir => 'initlog' },
	    { subdir => 'rrd' },
	    { subdir => 'rrddata' },
	    { subdir => 'firewall' },
	    { subdir => 'snapshot' },
	    ];

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'rrd',
    path => '{vmid}/rrd',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    description => "Read VM RRD statistics (returns PNG)",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    ds => {
		description => "The list of datasources you want to display.",
 		type => 'string', format => 'pve-configid-list',
	    },
	    cf => {
		description => "The RRD consolidation function",
 		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    filename => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	return PVE::Cluster::create_rrd_graph(
	    "pve2-vm/$param->{vmid}", $param->{timeframe},
	    $param->{ds}, $param->{cf});

    }});

__PACKAGE__->register_method({
    name => 'rrddata',
    path => '{vmid}/rrddata',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    description => "Read VM RRD statistics",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    cf => {
		description => "The RRD consolidation function",
 		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	return PVE::Cluster::create_rrd_data(
	    "pve2-vm/$param->{vmid}", $param->{timeframe}, $param->{cf});
    }});


__PACKAGE__->register_method({
    name => 'vm_config',
    path => '{vmid}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get container configuration.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => "object",
	properties => {
	    digest => {
		type => 'string',
		description => 'SHA1 digest of configuration file. This can be used to prevent concurrent modifications.',
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::LXC::load_config($param->{vmid});

	delete $conf->{snapshots};
	delete $conf->{lxc};

	return $conf;
    }});

__PACKAGE__->register_method({
    name => 'destroy_vm',
    path => '{vmid}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Destroy the container (also delete all uses files).",
    permissions => {
	check => [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};

	# test if container exists
	my $conf = PVE::LXC::load_config($vmid);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $code = sub {
	    # reload config after lock
	    $conf = PVE::LXC::load_config($vmid);
	    PVE::LXC::check_lock($conf);

	    PVE::LXC::destroy_lxc_container($storage_cfg, $vmid, $conf);
	    PVE::AccessControl::remove_vm_from_pool($vmid);
	};

	my $realcmd = sub { PVE::LXC::lock_container($vmid, 1, $code); };
	
	return $rpcenv->fork_worker('vzdestroy', $vmid, $authuser, $realcmd);
    }});

my $sslcert;

__PACKAGE__->register_method ({
    name => 'vncproxy',
    path => '{vmid}/vncproxy',
    method => 'POST',
    protected => 1,
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Creates a TCP VNC proxy connections.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    websocket => {
		optional => 1,
		type => 'boolean',
		description => "use websocket instead of standard VNC.",
	    },
	},
    },
    returns => {
    	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    cert => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};
	my $node = $param->{node};

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	$sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
	    if !$sslcert;

	my ($remip, $family);

	if ($node ne PVE::INotify::nodename()) {
	    ($remip, $family) = PVE::Cluster::remote_node_ip($node);
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	# NOTE: vncterm VNC traffic is already TLS encrypted,
	# so we select the fastest chipher here (or 'none'?)
	my $remcmd = $remip ?
	    ['/usr/bin/ssh', '-t', $remip] : [];

	my $shcmd = [ '/usr/bin/dtach', '-A',
		      "/var/run/dtach/vzctlconsole$vmid",
		      '-r', 'winch', '-z',
		      'lxc-console', '-n', $vmid ];

	my $realcmd = sub {
	    my $upid = shift;

	    syslog ('info', "starting lxc vnc proxy $upid\n");

	    my $timeout = 10;

	    my $cmd = ['/usr/bin/vncterm', '-rfbport', $port,
		       '-timeout', $timeout, '-authpath', $authpath,
		       '-perm', 'VM.Console'];

	    if ($param->{websocket}) {
		$ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm
		push @$cmd, '-notls', '-listen', 'localhost';
	    }

	    push @$cmd, '-c', @$remcmd, @$shcmd;

	    run_command($cmd);

	    return;
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	    cert => $sslcert,
	};
    }});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => '{vmid}/vncwebsocket',
    method => 'GET',
    permissions => {
	description => "You also need to pass a valid ticket (vncticket).",
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    vncticket => {
		description => "Ticket from previous call to vncproxy.",
		type => 'string',
		maxLength => 512,
	    },
	    port => {
		description => "Port number returned by previous vncproxy call.",
		type => 'integer',
		minimum => 5900,
		maximum => 5999,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    port => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $authpath = "/vms/$param->{vmid}";

	PVE::AccessControl::verify_vnc_ticket($param->{vncticket}, $authuser, $authpath);

	my $port = $param->{port};

	return { port => $port };
    }});

__PACKAGE__->register_method ({
    name => 'spiceproxy',
    path => '{vmid}/spiceproxy',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Returns a SPICE configuration to connect to the CT.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    proxy => get_standard_option('spice-proxy', { optional => 1 }),
	},
    },
    returns => get_standard_option('remote-viewer-config'),
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};
	my $node = $param->{node};
	my $proxy = $param->{proxy};

	my $authpath = "/vms/$vmid";
	my $permissions = 'VM.Console';

	my $shcmd = ['/usr/bin/dtach', '-A',
		     "/var/run/dtach/vzctlconsole$vmid",
		     '-r', 'winch', '-z',
		     'lxc-console', '-n', $vmid];

	my $title = "CT $vmid";

	return PVE::API2Tools::run_spiceterm($authpath, $permissions, $vmid, $node, $proxy, $title, $shcmd);
    }});

__PACKAGE__->register_method({
    name => 'vmcmdidx',
    path => '{vmid}/status',
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
    permissions => {
	user => 'all',
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::LXC::load_config($param->{vmid});

	my $res = [
	    { subdir => 'current' },
	    { subdir => 'start' },
	    { subdir => 'stop' },
	    { subdir => 'shutdown' },
	    { subdir => 'migrate' },
	    ];

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'vm_status',
    path => '{vmid}/status/current',
    method => 'GET',
    proxyto => 'node',
    protected => 1, # openvz /proc entries are only readable by root
    description => "Get virtual machine status.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => { type => 'object' },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::LXC::load_config($param->{vmid});

	my $vmstatus =  PVE::LXC::vmstatus($param->{vmid});
	my $status = $vmstatus->{$param->{vmid}};

	$status->{ha} = PVE::HA::Config::vm_is_ha_managed($param->{vmid}) ? 1 : 0;

	return $status;
    }});

__PACKAGE__->register_method({
    name => 'vm_start',
    path => '{vmid}/status/start',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Start the container.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	die "CT $vmid already running\n" if PVE::LXC::check_running($vmid);

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "ct:$vmid";

		my $cmd = ['ha-manager', 'enable', $service];

		print "Executing HA start for CT $vmid\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hastart', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "starting CT $vmid: $upid\n");

		my $conf = PVE::LXC::load_config($vmid);
		my $storage_cfg = cfs_read_file("storage.cfg");
		if (my $sid = &$get_container_storage($storage_cfg, $vmid, $conf)) {
		    PVE::Storage::activate_storage($storage_cfg, $sid);
		}

		PVE::LXC::update_lxc_config($storage_cfg, $vmid, $conf);

		my $cmd = ['lxc-start', '-n', $vmid];

		run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('vzstart', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_stop',
    path => '{vmid}/status/stop',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Stop the container.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "ct:$vmid";

		my $cmd = ['ha-manager', 'disable', $service];

		print "Executing HA stop for CT $vmid\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hastop', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "stoping CT $vmid: $upid\n");

		my $cmd = ['lxc-stop', '-n', $vmid, '--kill'];

		run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('vzstop', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_shutdown',
    path => '{vmid}/status/shutdown',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Shutdown the container.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    timeout => {
		description => "Wait maximal timeout seconds.",
		type => 'integer',
		minimum => 0,
		optional => 1,
		default => 60,
	    },
	    forceStop => {
		description => "Make sure the Container stops.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $timeout = extract_param($param, 'timeout');

	die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "shutdown CT $vmid: $upid\n");

	    my $cmd = ['lxc-stop', '-n', $vmid];

	    $timeout = 60 if !defined($timeout);

	    push @$cmd, '--timeout', $timeout;

	    eval { run_command($cmd, timeout => $timeout+5); };
	    my $err = $@;
	    return if !$err;

	    die $err if !$param->{forceStop};

	    warn "shutdown failed - forcing stop now\n";

	    push @$cmd, '--kill';
	    run_command($cmd);

	    return;
	};

	my $upid = $rpcenv->fork_worker('vzshutdown', $vmid, $authuser, $realcmd);

	return $upid;
    }});

__PACKAGE__->register_method({
    name => 'vm_suspend',
    path => '{vmid}/status/suspend',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Suspend the container.",
    permissions => {
        check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

        my $realcmd = sub {
            my $upid = shift;

            syslog('info', "suspend CT $vmid: $upid\n");

	    my $cmd = ['lxc-checkpoint', '-n', $vmid, '-s', '-D', '/var/liv/vz/dump'];

	    run_command($cmd);

            return;
        };

        my $upid = $rpcenv->fork_worker('vzsuspend', $vmid, $authuser, $realcmd);

        return $upid;
    }});

__PACKAGE__->register_method({
    name => 'vm_resume',
    path => '{vmid}/status/resume',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Resume the container.",
    permissions => {
        check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        die "CT $vmid already running\n" if PVE::LXC::check_running($vmid);

        my $realcmd = sub {
            my $upid = shift;

            syslog('info', "resume CT $vmid: $upid\n");

	    my $cmd = ['lxc-checkpoint', '-n', $vmid, '-r', '--foreground',
		       '-D', '/var/liv/vz/dump'];

	    run_command($cmd);

            return;
        };

        my $upid = $rpcenv->fork_worker('vzresume', $vmid, $authuser, $realcmd);

        return $upid;
    }});

__PACKAGE__->register_method({
    name => 'migrate_vm',
    path => '{vmid}/migrate',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Migrate the container to another node. Creates a new migration task.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Migrate' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    target => get_standard_option('pve-node', { description => "Target node." }),
	    online => {
		type => 'boolean',
		description => "Use online/live migration.",
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

	my $authuser = $rpcenv->get_user();

	my $target = extract_param($param, 'target');

	my $localnode = PVE::INotify::nodename();
	raise_param_exc({ target => "target is local node."}) if $target eq $localnode;

	PVE::Cluster::check_cfs_quorum();

	PVE::Cluster::check_node_exists($target);

	my $targetip = PVE::Cluster::remote_node_ip($target);

	my $vmid = extract_param($param, 'vmid');

	# test if VM exists
	PVE::LXC::load_config($vmid);

	# try to detect errors early
	if (PVE::LXC::check_running($vmid)) {
	    die "cant migrate running container without --online\n"
		if !$param->{online};
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "ct:$vmid";

		my $cmd = ['ha-manager', 'migrate', $service, $target];

		print "Executing HA migrate for CT $vmid to node $target\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hamigrate', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		# fixme: implement lxc container migration
		die "lxc container migration not implemented\n";

		return;
	    };

	    return $rpcenv->fork_worker('vzmigrate', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'snapshot',
    path => '{vmid}/snapshot',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Snapshot a container.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
#	    vmstate => {
#		optional => 1,
#		type => 'boolean',
#		description => "Save the vmstate",
#	    },
	    description => {
		optional => 1,
		type => 'string',
		description => "A textual description or comment.",
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

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	die "unable to use snapshot name 'current' (reserved name)\n"
	    if $snapname eq 'current';

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "snapshot container $vmid: $snapname");
	    PVE::LXC::snapshot_create($vmid, $snapname, $param->{description});
	};

	return $rpcenv->fork_worker('pctsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'delsnapshot',
    path => '{vmid}/snapshot/{snapname}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Delete a LXC snapshot.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
	    force => {
		optional => 1,
		type => 'boolean',
		description => "For removal from config file, even if removing disk snapshots fails.",
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

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "delete snapshot VM $vmid: $snapname");
	    PVE::LXC::snapshot_delete($vmid, $snapname, $param->{force});
	};

	return $rpcenv->fork_worker('lxcdelsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'rollback',
    path => '{vmid}/snapshot/{snapname}/rollback',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Rollback LXC state to specified snapshot.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
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

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "rollback snapshot LXC $vmid: $snapname");
	    PVE::LXC::snapshot_rollback($vmid, $snapname);
	};

	return $rpcenv->fork_worker('lxcrollback', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'snapshot_list',
    path => '{vmid}/snapshot',
    method => 'GET',
    description => "List all snapshots.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    proxyto => 'node',
    protected => 1, # lxc pid files are only readable by root
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid'),
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $conf = PVE::LXC::load_config($vmid);
	my $snaphash = $conf->{snapshots} || {};

	my $res = [];

	foreach my $name (keys %$snaphash) {
	    my $d = $snaphash->{$name};
	    my $item = {
		name => $name,
		snaptime => $d->{snaptime} || 0,
		description => $d->{description} || '',
	    };
	    $item->{parent} = $d->{parent} if defined($d->{parent});
	    $item->{snapstate} = $d->{snapstate} if $d->{snapstate};
	    push @$res, $item;
	}

	my $running = PVE::LXC::check_running($vmid) ? 1 : 0;
	my $current = { name => 'current', digest => $conf->{digest}, running => $running };
	$current->{parent} = $conf->{parent} if defined($conf->{parent});

	push @$res, $current;

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'snapshot_cmd_idx',
    path => '{vmid}/snapshot/{snapname}',
    description => '',
    method => 'GET',
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid'),
	    node => get_standard_option('pve-node'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{cmd}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	push @$res, { cmd => 'rollback' };
	push @$res, { cmd => 'config' };

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'update_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Update snapshot metadata.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
	    description => {
		optional => 1,
		type => 'string',
		description => "A textual description or comment.",
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	return undef if !defined($param->{description});

	my $updatefn =  sub {

	    my $conf = PVE::LXC::load_config($vmid);
	    PVE::LXC::check_lock($conf);

	    my $snap = $conf->{snapshots}->{$snapname};

	    die "snapshot '$snapname' does not exist\n" if !defined($snap);

	    $snap->{description} = $param->{description} if defined($param->{description});

	    PVE::LXC::write_config($vmid, $conf, 1);
	};

	PVE::LXC::lock_container($vmid, 10, $updatefn);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get snapshot configuration",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-lxc-snapshot-name'),
	},
    },
    returns => { type => "object" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $conf = PVE::LXC::load_config($vmid);

	my $snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	delete $snap->{lxc};
	
	return $snap;
    }});

__PACKAGE__->register_method({
    name => 'vm_feature',
    path => '{vmid}/feature',
    method => 'GET',
    proxyto => 'node',
    protected => 1,
    description => "Check if feature for virtual machine is available.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
            feature => {
                description => "Feature to check.",
                type => 'string',
                enum => [ 'snapshot' ],
            },
            snapname => get_standard_option('pve-lxc-snapshot-name', {
                optional => 1,
            }),
	},
    },
    returns => {
	type => "object",
	properties => {
	    hasFeature => { type => 'boolean' },
	    #nodes => {
		#type => 'array',
		#items => { type => 'string' },
	    #}
	},
    },
    code => sub {
	my ($param) = @_;

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $feature = extract_param($param, 'feature');

	my $conf = PVE::LXC::load_config($vmid);

	if($snapname){
	    my $snap = $conf->{snapshots}->{$snapname};
	    die "snapshot '$snapname' does not exist\n" if !defined($snap);
	    $conf = $snap;
	}
	my $storecfg = PVE::Storage::config();
	#Maybe include later
	#my $nodelist = PVE::LXC::shared_nodes($conf, $storecfg);
	my $hasFeature = PVE::LXC::has_feature($feature, $conf, $storecfg, $snapname);

	return {
	    hasFeature => $hasFeature,
	    #nodes => [ keys %$nodelist ],
	};
    }});
1;
