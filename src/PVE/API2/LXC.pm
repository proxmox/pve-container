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
use PVE::LXC::Migrate;
use PVE::API2::LXC::Config;
use PVE::API2::LXC::Status;
use PVE::API2::LXC::Snapshot;
use PVE::HA::Env::PVE2;
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
	properties => PVE::LXC::Config->json_config_properties({
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::Cluster::complete_next_vmid }),
	    ostemplate => {
		description => "The OS template or backup file.",
		type => 'string',
		maxLength => 255,
		completion => \&PVE::LXC::complete_os_templates,
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
		completion => \&PVE::Storage::complete_storage_enabled,
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
	    'ignore-unpack-errors' => {
		optional => 1,
		type => 'boolean',
		description => "Ignore errors when extracting the template.",
	    },
	    'ssh-public-keys' => {
		optional => 1,
		type => 'string',
		description => "Setup public SSH keys (one key per line, " .
				"OpenSSH format).",
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

	my $ignore_unpack_errors = extract_param($param, 'ignore-unpack-errors');

	my $basecfg_fn = PVE::LXC::Config->config_file($vmid);

	my $same_container_exists = -f $basecfg_fn;

	# 'unprivileged' is read-only, so we can't pass it to update_pct_config
	my $unprivileged = extract_param($param, 'unprivileged');

	my $restore = extract_param($param, 'restore');

	if ($restore) {
	    # fixme: limit allowed parameters

	}
	
	my $force = extract_param($param, 'force');

	if (!($same_container_exists && $restore && $force)) {
	    PVE::Cluster::check_vmid_unused($vmid);
	} else {
	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_protection($conf, "unable to restore CT $vmid");
	}

	my $password = extract_param($param, 'password');

	my $ssh_keys = extract_param($param, 'ssh-public-keys');
	PVE::Tools::validate_ssh_public_keys($ssh_keys) if defined($ssh_keys);

	my $pool = extract_param($param, 'pool');

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	    $rpcenv->check_perm_modify($authuser, "/pool/$pool");
	}

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

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, $pool, $param, []);

	my $storage = extract_param($param, 'storage') // 'local';

	my $storage_cfg = cfs_read_file("storage.cfg");

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

	my $check_and_activate_storage = sub {
	    my ($sid) = @_;

	    my $scfg = PVE::Storage::storage_check_node($storage_cfg, $sid, $node);

	    raise_param_exc({ storage => "storage '$sid' does not support container directories"})
		if !$scfg->{content}->{rootdir};

	    $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

	    PVE::Storage::activate_storage($storage_cfg, $sid);
	};

	my $conf = {};

	my $no_disk_param = {};
	my $mp_param = {};
	my $storage_only_mode = 1;
	foreach my $opt (keys %$param) {
	    my $value = $param->{$opt};
	    if ($opt eq 'rootfs' || $opt =~ m/^mp\d+$/) {
		# allow to use simple numbers (add default storage in that case)
		if ($value =~ m/^\d+(\.\d+)?$/) {
		    $mp_param->{$opt} = "$storage:$value";
		} else {
		    $mp_param->{$opt} = $value;
		}
		$storage_only_mode = 0;
	    } elsif ($opt =~ m/^unused\d+$/) {
		warn "ignoring '$opt', cannot create/restore with unused volume\n";
		delete $param->{$opt};
	    } else {
		$no_disk_param->{$opt} = $value;
	    }
	}

	die "mountpoints configured, but 'rootfs' not set - aborting\n"
	    if !$storage_only_mode && !defined($mp_param->{rootfs});

	# check storage access, activate storage
	my $delayed_mp_param = {};
	PVE::LXC::Config->foreach_mountpoint($mp_param, sub {
	    my ($ms, $mountpoint) = @_;

	    my $volid = $mountpoint->{volume};
	    my $mp = $mountpoint->{mp};

	    if ($mountpoint->{type} ne 'volume') { # bind or device
		die "Only root can pass arbitrary filesystem paths.\n"
		    if $authuser ne 'root@pam';
	    } else {
		my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
		&$check_and_activate_storage($sid);
	    }
	});

	# check/activate default storage
	&$check_and_activate_storage($storage) if !defined($mp_param->{rootfs});

	PVE::LXC::Config->update_pct_config($vmid, $conf, 0, $no_disk_param);

	$conf->{unprivileged} = 1 if $unprivileged;

	my $check_vmid_usage = sub {
	    if ($force) {
		die "can't overwrite running container\n"
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
		if ($storage_only_mode) {
		    if ($restore) {
			(undef, $mp_param) = PVE::LXC::Create::recover_config($archive);
			die "rootfs configuration could not be recovered, please check and specify manually!\n"
			    if !defined($mp_param->{rootfs});
			PVE::LXC::Config->foreach_mountpoint($mp_param, sub {
			    my ($ms, $mountpoint) = @_;
			    my $type = $mountpoint->{type};
			    if ($type eq 'volume') {
				die "unable to detect disk size - please specify $ms (size)\n"
				    if !defined($mountpoint->{size});
				my $disksize = $mountpoint->{size} / (1024 * 1024 * 1024); # create_disks expects GB as unit size
				delete $mountpoint->{size};
				$mountpoint->{volume} = "$storage:$disksize";
				$mp_param->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
			    } else {
				my $type = $mountpoint->{type};
				die "restoring rootfs to $type mount is only possible by specifying -rootfs manually!\n"
				    if ($ms eq 'rootfs');

				if ($mountpoint->{backup}) {
				    warn "WARNING - unsupported configuration!\n";
				    warn "backup was enabled for $type mountpoint $ms ('$mountpoint->{mp}')\n";
				    warn "mountpoint configuration will be restored after archive extraction!\n";
				    warn "contained files will be restored to wrong directory!\n";
				}
				$delayed_mp_param->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
			    }
			});
		    } else {
			$mp_param->{rootfs} = "$storage:4"; # defaults to 4GB
		    }
		}

		$vollist = PVE::LXC::create_disks($storage_cfg, $vmid, $mp_param, $conf);


		PVE::LXC::Create::create_rootfs($storage_cfg, $vmid, $conf,
						$archive, $password, $restore,
						$ignore_unpack_errors, $ssh_keys);
		# set some defaults
		$conf->{hostname} ||= "CT$vmid";
		$conf->{memory} ||= 512;
		$conf->{swap} //= 512;
		foreach my $mp (keys %$delayed_mp_param) {
		    $conf->{$mp} = $delayed_mp_param->{$mp};
		}
		PVE::LXC::Config->write_config($vmid, $conf);
	    };
	    if (my $err = $@) {
		PVE::LXC::destroy_disks($storage_cfg, $vollist);
		PVE::LXC::destroy_config($vmid);
		die $err;
	    }
	    PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	};

	my $realcmd = sub { PVE::LXC::Config->lock_config($vmid, $code); };

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
	my $conf = PVE::LXC::Config->load_config($param->{vmid});

	my $res = [
	    { subdir => 'config' },
	    { subdir => 'status' },
	    { subdir => 'vncproxy' },
	    { subdir => 'vncwebsocket' },
	    { subdir => 'spiceproxy' },
	    { subdir => 'migrate' },
	    { subdir => 'clone' },
#	    { subdir => 'initlog' },
	    { subdir => 'rrd' },
	    { subdir => 'rrddata' },
	    { subdir => 'firewall' },
	    { subdir => 'snapshot' },
	    { subdir => 'resize' },
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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_stopped }),
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
	my $conf = PVE::LXC::Config->load_config($vmid);

	my $storage_cfg = cfs_read_file("storage.cfg");

	PVE::LXC::Config->check_protection($conf, "can't remove CT $vmid");

	die "unable to remove CT $vmid - used in HA resources\n"
	    if PVE::HA::Config::vm_is_ha_managed($vmid);

	my $running_error_msg = "unable to destroy CT $vmid - container is running\n";

	die $running_error_msg if PVE::LXC::check_running($vmid); # check early

	my $code = sub {
	    # reload config after lock
	    $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    die $running_error_msg if PVE::LXC::check_running($vmid);

	    PVE::LXC::destroy_lxc_container($storage_cfg, $vmid, $conf);
	    PVE::AccessControl::remove_vm_access($vmid);
	    PVE::Firewall::remove_vmfw_conf($vmid);
	};

	my $realcmd = sub { PVE::LXC::Config->lock_config($vmid, $code); };
	
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

	my $conf = PVE::LXC::Config->load_config($vmid, $node);
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

	my $conf = PVE::LXC::Config->load_config($vmid);

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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    target => get_standard_option('pve-node', {
		description => "Target node.",
		completion => \&PVE::Cluster::complete_migration_target,
	    }),
	    online => {
		type => 'boolean',
		description => "Use online/live migration.",
		optional => 1,
	    },
	    force => {
		type => 'boolean',
		description => "Force migration despite local bind / device" .
		    " mounts. WARNING: identical bind / device mounts need to ".
		    " be available on the target node.",
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
	PVE::LXC::Config->load_config($vmid);

	# try to detect errors early
	if (PVE::LXC::check_running($vmid)) {
	    die "can't migrate running container without --online\n"
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

		PVE::LXC::Migrate->migrate($target, $targetip, $vmid, $param);

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

	my $conf = PVE::LXC::Config->load_config($vmid);

	if($snapname){
	    my $snap = $conf->{snapshots}->{$snapname};
	    die "snapshot '$snapname' does not exist\n" if !defined($snap);
	    $conf = $snap;
	}
	my $storage_cfg = PVE::Storage::config();
	#Maybe include later
	#my $nodelist = PVE::LXC::shared_nodes($conf, $storage_cfg);
	my $hasFeature = PVE::LXC::Config->has_feature($feature, $conf, $storage_cfg, $snapname);

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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_stopped }),
	    experimental => {
		type => 'boolean',
		description => "The template feature is experimental, set this " .
		    "flag if you know what you are doing.",
		default => 0,
	    },
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

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    die "unable to create template, because CT contains snapshots\n"
		if $conf->{snapshots} && scalar(keys %{$conf->{snapshots}});

	    die "you can't convert a template to a template\n"
		if PVE::LXC::Config->is_template($conf);

	    die "you can't convert a CT to template if the CT is running\n"
		if PVE::LXC::check_running($vmid);

	    my $realcmd = sub {
		PVE::LXC::template_create($vmid, $conf);
	    };

	    $conf->{template} = 1;

	    PVE::LXC::Config->write_config($vmid, $conf);
	    # and remove lxc config
	    PVE::LXC::update_lxc_config(undef, $vmid, $conf);

	    return $rpcenv->fork_worker('vztemplate', $vmid, $authuser, $realcmd);
	};

	PVE::LXC::Config->lock_config($vmid, $updatefn);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'clone_vm',
    path => '{vmid}/clone',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a container clone/copy",
    permissions => {
	description => "You need 'VM.Clone' permissions on /vms/{vmid}, " .
	    "and 'VM.Allocate' permissions " .
	    "on /vms/{newid} (or on the VM pool /pool/{pool}). You also need " .
	    "'Datastore.AllocateSpace' on any used storage.",
	check =>
	[ 'and',
	  ['perm', '/vms/{vmid}', [ 'VM.Clone' ]],
	  [ 'or',
	    [ 'perm', '/vms/{newid}', ['VM.Allocate']],
	    [ 'perm', '/pool/{pool}', ['VM.Allocate'], require_param => 'pool'],
	  ],
	]
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    newid => get_standard_option('pve-vmid', {
		completion => \&PVE::Cluster::complete_next_vmid,
		description => 'VMID for the clone.' }),
	    hostname => {
		optional => 1,
		type => 'string', format => 'dns-name',
		description => "Set a hostname for the new CT.",
	    },
	    description => {
		optional => 1,
		type => 'string',
		description => "Description for the new CT.",
	    },
	    pool => {
		optional => 1,
		type => 'string', format => 'pve-poolid',
		description => "Add the new CT to the specified pool.",
	    },
	    snapname => get_standard_option('pve-lxc-snapshot-name', {
		optional => 1,
            }),
	    storage => get_standard_option('pve-storage-id', {
		description => "Target storage for full clone.",
		requires => 'full',
		optional => 1,
	    }),
	    full => {
		optional => 1,
	        type => 'boolean',
	        description => "Create a full copy of all disk. This is always done when " .
		    "you clone a normal CT. For CT templates, we try to create a linked clone by default.",
		default => 0,
	    },
	    experimental => {
		type => 'boolean',
		description => "The clone feature is experimental, set this " .
		    "flag if you know what you are doing.",
		default => 0,
	    },
#	    target => get_standard_option('pve-node', {
#		description => "Target node. Only allowed if the original VM is on shared storage.",
#		optional => 1,
#	    }),
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

	my $newid = extract_param($param, 'newid');

	my $pool = extract_param($param, 'pool');

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	}

	my $snapname = extract_param($param, 'snapname');

	my $storage = extract_param($param, 'storage');

        my $localnode = PVE::INotify::nodename();

	my $storecfg = PVE::Storage::config();

	if ($storage) {
	    # check if storage is enabled on local node
	    PVE::Storage::storage_check_enabled($storecfg, $storage);
	}

	PVE::Cluster::check_cfs_quorum();

	my $running = PVE::LXC::check_running($vmid) || 0;

	my $clonefn = sub {

	    # do all tests after lock
	    # we also try to do all tests before we fork the worker
	    my $conf = PVE::LXC::Config->load_config($vmid);

	    PVE::LXC::Config->check_lock($conf);

	    my $verify_running = PVE::LXC::check_running($vmid) || 0;

	    die "unexpected state change\n" if $verify_running != $running;

	    die "snapshot '$snapname' does not exist\n"
		if $snapname && !defined( $conf->{snapshots}->{$snapname});

	    my $oldconf = $snapname ? $conf->{snapshots}->{$snapname} : $conf;

	    my $conffile = PVE::LXC::Config->config_file($newid);
	    die "unable to create CT $newid: config file already exists\n"
		if -f $conffile;

	    my $newconf = { lock => 'clone' };
	    my $mountpoints = {};
	    my $fullclone = {};
	    my $vollist = [];

	    foreach my $opt (keys %$oldconf) {
		my $value = $oldconf->{$opt};

		# no need to copy unused images, because VMID(owner) changes anyways
		next if $opt =~ m/^unused\d+$/;

		if (($opt eq 'rootfs') || ($opt =~ m/^mp\d+$/)) {
		    my $mp = $opt eq 'rootfs' ?
			PVE::LXC::Config->parse_ct_rootfs($value) :
			PVE::LXC::Config->parse_ct_mountpoint($value);

		    if ($mp->{type} eq 'volume') {
			my $volid = $mp->{volume};
			if ($param->{full}) {
			    die "fixme: full clone not implemented";

			    die "Full clone feature for '$volid' is not available\n"
				if !PVE::Storage::volume_has_feature($storecfg, 'copy', $volid, $snapname, $running);
			    $fullclone->{$opt} = 1;
			} else {
			    # not full means clone instead of copy
			    die "Linked clone feature for '$volid' is not available\n"
				if !PVE::Storage::volume_has_feature($storecfg, 'clone', $volid, $snapname, $running);
			}

			$mountpoints->{$opt} = $mp;
			push @$vollist, $volid;

		    } else {
			# TODO: allow bind mounts?
			die "unable to clone mountpint '$opt' (type $mp->{type})\n";
		    }

		} else {
		    # copy everything else
		    $newconf->{$opt} = $value;
		}
	    }

	    delete $newconf->{template};
	    if ($param->{hostname}) {
		$newconf->{hostname} = $param->{hostname};
	    }

	    if ($param->{description}) {
		$newconf->{description} = $param->{description};
	    }

	    # create empty/temp config - this fails if CT already exists on other node
	    PVE::Tools::file_set_contents($conffile, "# ctclone temporary file\nlock: clone\n");

	    my $realcmd = sub {
		my $upid = shift;

		my $newvollist = [];

		eval {
		    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub { die "interrupted by signal\n"; };

		    PVE::Storage::activate_volumes($storecfg, $vollist, $snapname);

		    foreach my $opt (keys %$mountpoints) {
			my $mp = $mountpoints->{$opt};
			my $volid = $mp->{volume};

			if ($fullclone->{$opt}) {
			    die "fixme: full clone not implemented\n";
			} else {
			    print "create linked clone of mountpoint $opt ($volid)\n";
			    my $newvolid = PVE::Storage::vdisk_clone($storecfg, $volid, $newid, $snapname);
			    push @$newvollist, $newvolid;
			    $mp->{volume} = $newvolid;

			    $newconf->{$opt} = PVE::LXC::Config->print_ct_mountpoint($mp, $opt eq 'rootfs');
			    PVE::LXC::Config->write_config($newid, $newconf);
			}
		    }

		    delete $newconf->{lock};
		    PVE::LXC::Config->write_config($newid, $newconf);

		    PVE::AccessControl::add_vm_to_pool($newid, $pool) if $pool;
		};
		if (my $err = $@) {
		    unlink $conffile;

		    sleep 1; # some storage like rbd need to wait before release volume - really?

		    foreach my $volid (@$newvollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "clone failed: $err";
		}

		return;
	    };

	    PVE::Firewall::clone_vmfw_conf($vmid, $newid);

	    return $rpcenv->fork_worker('vzclone', $vmid, $authuser, $realcmd);

	};

	return PVE::LXC::Config->lock_config($vmid, $clonefn);
    }});


__PACKAGE__->register_method({
    name => 'resize_vm',
    path => '{vmid}/resize',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Resize a container mountpoint.",
    permissions => {
	check => ['perm', '/vms/{vmid}', ['VM.Config.Disk'], any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    disk => {
		type => 'string',
		description => "The disk you want to resize.",
		enum => [PVE::LXC::Config->mountpoint_names()],
	    },
	    size => {
		type => 'string',
		pattern => '\+?\d+(\.\d+)?[KMGT]?',
		description => "The new size. With the '+' sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.",
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    }
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

	my $digest = extract_param($param, 'digest');

	my $sizestr = extract_param($param, 'size');
	my $ext = ($sizestr =~ s/^\+//);
	my $newsize = PVE::JSONSchema::parse_size($sizestr);
	die "invalid size string" if !defined($newsize);

	die "no options specified\n" if !scalar(keys %$param);

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, $param, []);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $code = sub {

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    my $running = PVE::LXC::check_running($vmid);

	    my $disk = $param->{disk};
	    my $mp = $disk eq 'rootfs' ? PVE::LXC::Config->parse_ct_rootfs($conf->{$disk}) :
		PVE::LXC::Config->parse_ct_mountpoint($conf->{$disk});

	    my $volid = $mp->{volume};

	    my (undef, undef, $owner, undef, undef, undef, $format) =
		PVE::Storage::parse_volname($storage_cfg, $volid);

	    die "can't resize mountpoint owned by another container ($owner)"
		if $vmid != $owner;

	    die "can't resize volume: $disk if snapshot exists\n"
		if %{$conf->{snapshots}} && $format eq 'qcow2';

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

	    PVE::Storage::activate_volumes($storage_cfg, [$volid]);

	    my $size = PVE::Storage::volume_size_info($storage_cfg, $volid, 5);
	    $newsize += $size if $ext;
	    $newsize = int($newsize);

	    die "unable to shrink disk size\n" if $newsize < $size;

	    return if $size == $newsize;

	    PVE::Cluster::log_msg('info', $authuser, "update CT $vmid: resize --disk $disk --size $sizestr");
	    my $realcmd = sub {
		# Note: PVE::Storage::volume_resize doesn't do anything if $running=1, so
		# we pass 0 here (parameter only makes sense for qemu)
		PVE::Storage::volume_resize($storage_cfg, $volid, $newsize, 0);

		$mp->{size} = $newsize;
		$conf->{$disk} = PVE::LXC::Config->print_ct_mountpoint($mp, $disk eq 'rootfs');

		PVE::LXC::Config->write_config($vmid, $conf);

		if ($format eq 'raw') {
		    my $path = PVE::Storage::path($storage_cfg, $volid, undef);
		    if ($running) {

			$mp->{mp} = '/';
			my $use_loopdev = (PVE::LXC::mountpoint_mount_path($mp, $storage_cfg))[1];
			$path = PVE::LXC::query_loopdev($path) if $use_loopdev;
			die "internal error: CT running but mountpoint not attached to a loop device"
			    if !$path;
			PVE::Tools::run_command(['losetup', '--set-capacity', $path]) if $use_loopdev;

			# In order for resize2fs to know that we need online-resizing a mountpoint needs
			# to be visible to it in its namespace.
			# To not interfere with the rest of the system we unshare the current mount namespace,
			# mount over /tmp and then run resize2fs.

			# interestingly we don't need to e2fsck on mounted systems...
			my $quoted = PVE::Tools::shellquote($path);
			my $cmd = "mount --make-rprivate / && mount $quoted /tmp && resize2fs $quoted";
			eval {
			    PVE::Tools::run_command(['unshare', '-m', '--', 'sh', '-c', $cmd]);
			};
			warn "Failed to update the container's filesystem: $@\n" if $@;
		    } else {
			eval {
			    PVE::Tools::run_command(['e2fsck', '-f', '-y', $path]);
			    PVE::Tools::run_command(['resize2fs', $path]);
			};
			warn "Failed to update the container's filesystem: $@\n" if $@;
		    }
		}
	    };

	    return $rpcenv->fork_worker('resize', $vmid, $authuser, $realcmd);
	};

	return PVE::LXC::Config->lock_config($vmid, $code);;
    }});

1;
