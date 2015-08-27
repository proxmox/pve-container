package PVE::API2::LXC;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param run_command);
use PVE::Exception qw(raise raise_param_exc);
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::AccessControl;
use PVE::Firewall;
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::LXC;
use PVE::LXC::Create;
use PVE::API2::LXC::Config;
use PVE::API2::LXC::Status;
use PVE::API2::LXC::Snapshot;
use PVE::HA::Config;
use PVE::JSONSchema qw(get_standard_option);
use base qw(PVE::RESTHandler);

use Data::Dumper; # fixme: remove

__PACKAGE__->register_method ({
    subclass => "PVE::API2::LXC::Config",
    path => '{vmid}/config',			      
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::LXC::Status",
    path => '{vmid}/status',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::LXC::Snapshot",
    path => '{vmid}/snapshot',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::CT",
    path => '{vmid}/firewall',
});

my $destroy_disks = sub {
    my ($storecfg, $vollist) = @_;

    foreach my $volid (@$vollist) {
	eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	warn $@ if $@;
    }
};
 
my $create_disks = sub {
    my ($storecfg, $vmid, $settings, $conf) = @_;

    my $vollist = [];

    eval {
	PVE::LXC::foreach_mountpoint($settings, sub {
	    my ($ms, $mountpoint) = @_;

	    my $volid = $mountpoint->{volume};
	    my $mp = $mountpoint->{mp};

	    my ($storage, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	    return if !$storage;

	    if ($volid =~ m/^([^:\s]+):(\d+(\.\d+)?)$/) {
		my ($storeid, $size) = ($1, $2);

		$size = int($size*1024) * 1024;

		my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		# fixme: use better naming ct-$vmid-disk-X.raw?

		if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
		    if ($size > 0) {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw',
							   undef, $size);
		    } else {
			$volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
							   undef, 0);
		    }
		} elsif ($scfg->{type} eq 'zfspool') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'subvol',
					       undef, $size);
		} elsif ($scfg->{type} eq 'drbd') {

		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size);

		} elsif ($scfg->{type} eq 'rbd') {

		    die "krbd option must be enabled on storage type '$scfg->{type}'\n" if !$scfg->{krbd};
		    $volid = PVE::Storage::vdisk_alloc($storecfg, $storage, $vmid, 'raw', undef, $size);
		} else {
		    die "unable to create containers on storage type '$scfg->{type}'\n";
		}
		push @$vollist, $volid;
		$conf->{$ms} = PVE::LXC::print_ct_mountpoint({volume => $volid, size => $size, mp => $mp });
	    } else {
		# use specified/existing volid
	    }
	});
    };
    # free allocated images on error
    if (my $err = $@) {
        syslog('err', "VM $vmid creating disks failed");
	&$destroy_disks($storecfg, $vollist);
        die $err;
    }
    return $vollist;
};

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
	properties => PVE::LXC::json_config_properties({
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
		description => "Default Storage.",
		default => 'local',
		optional => 1,
	    }),
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

	my $storage = extract_param($param, 'storage') // 'local';
	
	my $storage_cfg = cfs_read_file("storage.cfg");

	my $scfg = PVE::Storage::storage_check_node($storage_cfg, $storage, $node);

	raise_param_exc({ storage => "storage '$storage' does not support container root directories"})
	    if !($scfg->{content}->{images} || $scfg->{content}->{rootdir});

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

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, $pool, [ keys %$param]);

	PVE::Storage::activate_storage($storage_cfg, $storage);

	my $ostemplate = extract_param($param, 'ostemplate');

	my $archive;

	if ($ostemplate eq '-') {
	    die "pipe requires cli environment\n" 
		if $rpcenv->{type} ne 'cli'; 
	    die "pipe can only be used with restore tasks\n" 
		if !$restore;
	    $archive = '-';
	    die "restore from pipe requires rootfs parameter\n" if !defined($param->{rootfs});
	} else {
	    $rpcenv->check_volume_access($authuser, $storage_cfg, $vmid, $ostemplate);
	    $archive = PVE::Storage::abs_filesystem_path($storage_cfg, $ostemplate);
	}

	my $conf = {};

	my $no_disk_param = {};
	foreach my $opt (keys %$param) {
	    my $value = $param->{$opt};
	    if ($opt eq 'rootfs' || $opt =~ m/^mp\d+$/) {
		# allow to use simple numbers (add default storage in that case)
		$param->{$opt} = "$storage:$value" if $value =~ m/^\d+(\.\d+)?$/;
	    } else {
		$no_disk_param->{$opt} = $value;
	    }
	}
	PVE::LXC::update_pct_config($vmid, $conf, 0, $no_disk_param);

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
	    my $vollist = [];

	    eval {
		if (!defined($param->{rootfs})) {
		    if ($restore) {
			my (undef, $disksize) = PVE::LXC::Create::recover_config($archive);
			die "unable to detect disk size - please specify rootfs (size)\n"
			    if !$disksize;
			$param->{rootfs} = "$storage:$disksize";
		    } else {
			$param->{rootfs} = "$storage:4"; # defaults to 4GB
		    }
		}

		$vollist = &$create_disks($storage_cfg, $vmid, $param, $conf);

		PVE::LXC::Create::create_rootfs($storage_cfg, $vmid, $conf, $archive, $password, $restore);
		# set some defaults
		$conf->{hostname} ||= "CT$vmid";
		$conf->{memory} ||= 512;
		$conf->{swap} //= 512;
		PVE::LXC::create_config($vmid, $conf);
	    };
	    if (my $err = $@) {
		&$destroy_disks($storage_cfg, $vollist);
		PVE::LXC::destroy_config($vmid);
		die $err;
	    }
	    PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	};

	my $realcmd = sub { PVE::LXC::lock_container($vmid, 1, $code); };

	&$check_vmid_usage(); # first check before locking

	return $rpcenv->fork_worker($restore ? 'vzrestore' : 'vzcreate',
				    $vmid, $authuser, $realcmd);

    }});

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
	    PVE::AccessControl::remove_vm_access($vmid);
	    PVE::Firewall::remove_vmfw_conf($vmid);
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

	my $conf = PVE::LXC::load_config($vmid, $node);
	my $concmd = PVE::LXC::get_console_command($vmid, $conf);

	my $shcmd = [ '/usr/bin/dtach', '-A',
		      "/var/run/dtach/vzctlconsole$vmid",
		      '-r', 'winch', '-z', @$concmd];

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

	my $conf = PVE::LXC::load_config($vmid);

	die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

	my $concmd = PVE::LXC::get_console_command($vmid, $conf);

	my $shcmd = ['/usr/bin/dtach', '-A',
		     "/var/run/dtach/vzctlconsole$vmid",
		     '-r', 'winch', '-z', @$concmd];

	my $title = "CT $vmid";

	return PVE::API2Tools::run_spiceterm($authpath, $permissions, $vmid, $node, $proxy, $title, $shcmd);
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
	my $storage_cfg = PVE::Storage::config();
	#Maybe include later
	#my $nodelist = PVE::LXC::shared_nodes($conf, $storage_cfg);
	my $hasFeature = PVE::LXC::has_feature($feature, $conf, $storage_cfg, $snapname);

	return {
	    hasFeature => $hasFeature,
	    #nodes => [ keys %$nodelist ],
	};
    }});

__PACKAGE__->register_method({
    name => 'template',
    path => '{vmid}/template',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a Template.",
    permissions => {
	description => "You need 'VM.Allocate' permissions on /vms/{vmid}",
	check => [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $updatefn =  sub {

	    my $conf = PVE::LXC::load_config($vmid);
	    PVE::LXC::check_lock($conf);

	    die "unable to create template, because CT contains snapshots\n"
		if $conf->{snapshots} && scalar(keys %{$conf->{snapshots}});

	    die "you can't convert a template to a template\n"
		if PVE::LXC::is_template($conf);

	    die "you can't convert a CT to template if the CT is running\n"
		if PVE::LXC::check_running($vmid);

	    my $realcmd = sub {
		PVE::LXC::template_create($vmid, $conf);
	    };

	    $conf->{template} = 1;

	    PVE::LXC::write_config($vmid, $conf);
	    # and remove lxc config
	    PVE::LXC::update_lxc_config(undef, $vmid, $conf);

	    return $rpcenv->fork_worker('vztemplate', $vmid, $authuser, $realcmd);
	};

	PVE::LXC::lock_container($vmid, undef, $updatefn);

	return undef;
    }});

1;
