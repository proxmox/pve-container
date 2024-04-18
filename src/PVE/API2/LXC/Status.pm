package PVE::API2::LXC::Status;

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
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

BEGIN {
    if (!$ENV{PVE_GENERATING_DOCS}) {
	require PVE::HA::Env::PVE2;
	import  PVE::HA::Env::PVE2;
	require PVE::HA::Config;
	import  PVE::HA::Config;
    }
}

__PACKAGE__->register_method({
    name => 'vmcmdidx',
    path => '',
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
	    { subdir => 'current' },
	    { subdir => 'start' },
	    { subdir => 'stop' },
	    { subdir => 'shutdown' },
	    { subdir => 'reboot' },
	    { subdir => 'migrate' },
	];

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'vm_status',
    path => 'current',
    method => 'GET',
    proxyto => 'node',
    protected => 1, # /proc entries are only readable by root
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
    returns => {
	type => 'object',
	properties => {
	    %$PVE::LXC::vmstatus_return_properties,
	    ha => {
		description => "HA manager service status.",
		type => 'object',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $vmid = $param->{vmid};
	my $conf = PVE::LXC::Config->load_config($vmid);

	my $vmstatus = PVE::LXC::vmstatus($vmid);
	my $status = $vmstatus->{$vmid};

	$status->{ha} = PVE::HA::Config::get_service_status("ct:$vmid");

	return $status;
    }});

__PACKAGE__->register_method({
    name => 'vm_start',
    path => 'start',
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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_stopped }),
	    skiplock => get_standard_option('skiplock'),
	    debug => {
		optional => 1,
		type => 'boolean',
		description => "If set, enables very verbose debug log-level on start.",
		default => 0,
	    },
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

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	die "CT $vmid already running\n" if PVE::LXC::check_running($vmid);

	PVE::Cluster::check_cfs_quorum();

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA start for CT $vmid\n";

		my $cmd = ['ha-manager', 'set',  "ct:$vmid", '--state', 'started'];
		PVE::Tools::run_command($cmd);
	    };

	    return $rpcenv->fork_worker('hastart', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		PVE::LXC::Config->lock_config($vmid, sub {
		    syslog('info', "starting CT $vmid: $upid\n");

		    my $conf = PVE::LXC::Config->load_config($vmid);

		    die "you can't start a CT if it's a template\n"
			if PVE::LXC::Config->is_template($conf);

		    if (!$skiplock && !PVE::LXC::Config->has_lock($conf, 'mounted')) {
			PVE::LXC::Config->check_lock($conf);
		    }

		    if ($conf->{unprivileged}) {
			PVE::LXC::Config->foreach_volume($conf, sub {
			    my ($ms, $mountpoint) = @_;
			    die "Quotas are not supported by unprivileged containers.\n"
				if $mountpoint->{quota};
			});
		    }

		    PVE::LXC::vm_start($vmid, $conf, $skiplock, $param->{debug});
		});
	    };

	    return $rpcenv->fork_worker('vzstart', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_stop',
    path => 'stop',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Stop the container. This will abruptly stop all processes running in the container.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	    skiplock => get_standard_option('skiplock'),
	    'overrule-shutdown' => {
		description => "Try to abort active 'vzshutdown' tasks before stopping.",
		optional => 1,
		type => 'boolean',
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

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $overrule_shutdown = extract_param($param, 'overrule-shutdown');

	die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    raise_param_exc({ 'overrule-shutdown' => "Not applicable for HA resources." })
		if $overrule_shutdown;

	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA stop for CT $vmid\n";

		my $cmd = ['ha-manager', 'crm-command', 'stop', "ct:$vmid", '0'];
		PVE::Tools::run_command($cmd);
	    };

	    return $rpcenv->fork_worker('hastop', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		if ($overrule_shutdown) {
		    my $overruled_tasks = PVE::GuestHelpers::abort_guest_tasks(
			$rpcenv, 'vzshutdown', $vmid);
		    my $overruled_tasks_list = join(", ", $overruled_tasks->@*);
		    print "overruled vzshutdown tasks: $overruled_tasks_list\n"
			if @$overruled_tasks;
		};

		PVE::LXC::Config->lock_config($vmid, sub {
		    syslog('info', "stopping CT $vmid: $upid\n");

		    my $conf = PVE::LXC::Config->load_config($vmid);
		    if (!$skiplock && !PVE::LXC::Config->has_lock($conf, 'mounted')) {
			PVE::LXC::Config->check_lock($conf);
		    }

		    PVE::LXC::vm_stop($vmid, 1);
		});
	    };

	    return $rpcenv->fork_worker('vzstop', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_shutdown',
    path => 'shutdown',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Shutdown the container. This will trigger a clean shutdown " .
	"of the container, see lxc-stop(1) for details.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
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

	my $timeout = extract_param($param, 'timeout') // 60;

	die "CT $vmid not running\n" if !PVE::LXC::check_running($vmid);

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {
	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA stop for CT $vmid\n";

		my $cmd = ['ha-manager', 'crm-command', 'stop',  "ct:$vmid", "$timeout"];
		PVE::Tools::run_command($cmd);
	    };

	    return $rpcenv->fork_worker('hastop', $vmid, $authuser, $hacmd);
	}

	my $realcmd = sub {
	    my $upid = shift;

	    PVE::LXC::Config->lock_config($vmid, sub {
		syslog('info', "shutdown CT $vmid: $upid\n");

		my $conf = PVE::LXC::Config->load_config($vmid);
		PVE::LXC::Config->check_lock($conf);

		PVE::LXC::vm_stop($vmid, 0, $timeout, $param->{forceStop});
	    });
	};

	return $rpcenv->fork_worker('vzshutdown', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_suspend',
    path => 'suspend',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Suspend the container. This is experimental.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
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

	    PVE::LXC::Config->lock_config($vmid, sub {
		syslog('info', "suspend CT $vmid: $upid\n");

		my $conf = PVE::LXC::Config->load_config($vmid);
		PVE::LXC::Config->check_lock($conf);

		my $cmd = ['lxc-checkpoint', '-n', $vmid, '-s', '-D', '/var/lib/vz/dump'];
		run_command($cmd);
	    });
	};

	return $rpcenv->fork_worker('vzsuspend', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_resume',
    path => 'resume',
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

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	die "CT $vmid already running\n" if PVE::LXC::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "resume CT $vmid: $upid\n");

	    my $cmd = ['lxc-checkpoint', '-n', $vmid, '-r', '--foreground', '-D', '/var/lib/vz/dump'];
	    run_command($cmd);
	};

	my $upid = $rpcenv->fork_worker('vzresume', $vmid, $authuser, $realcmd);

	return $upid;
    }});

__PACKAGE__->register_method({
    name => 'vm_reboot',
    path => 'reboot',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Reboot the container by shutting it down, and starting it again. Applies pending changes.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::LXC::complete_ctid_running }),
	    timeout => {
		description => "Wait maximal timeout seconds for the shutdown.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
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

	die "VM $vmid not running\n" if !PVE::LXC::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "requesting reboot of CT $vmid: $upid\n");
	    PVE::LXC::vm_reboot($vmid, $param->{timeout});
	    return;
	};

	return $rpcenv->fork_worker('vzreboot', $vmid, $authuser, $realcmd);
    }});



1;
