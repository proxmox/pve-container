package PVE::API2::LXC::Snapshot;

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

__PACKAGE__->register_method({
    name => 'list',
    path => '',
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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
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

	my $conf = PVE::LXC::Config->load_config($vmid);
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

use Data::Dumper; # fixme: remove
__PACKAGE__->register_method({
    name => 'snapshot',
    path => '',
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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
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

	die "unable to use snapshot name 'vzdump' (reserved name)\n"
	    if $snapname eq 'vzdump';

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "snapshot container $vmid: $snapname");
	    PVE::LXC::Config->snapshot_create($vmid, $snapname, 0, $param->{description});
	};

	return $rpcenv->fork_worker('vzsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'delsnapshot',
    path => '{snapname}',
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
	    PVE::LXC::Config->snapshot_delete($vmid, $snapname, $param->{force});
	};

	return $rpcenv->fork_worker('vzdelsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'snapshot_cmd_idx',
    path => '{snapname}',
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
    name => 'rollback',
    path => '{snapname}/rollback',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Rollback LXC state to specified snapshot.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot', 'VM.Snapshot.Rollback' ], any => 1],
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
	    PVE::LXC::Config->snapshot_rollback($vmid, $snapname);
	};

	my $worker = sub {
	    # hold migration lock, this makes sure that nobody create replication snapshots
	    return PVE::GuestHelpers::guest_migration_lock($vmid, 10, $realcmd);
	};

	return $rpcenv->fork_worker('vzrollback', $vmid, $authuser, $worker);
    }});

__PACKAGE__->register_method({
    name => 'update_snapshot_config',
    path => '{snapname}/config',
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

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    my $snap = $conf->{snapshots}->{$snapname};

	    die "snapshot '$snapname' does not exist\n" if !defined($snap);

	    $snap->{description} = $param->{description} if defined($param->{description});

	    PVE::LXC::Config->write_config($vmid, $conf, 1);
	};

	PVE::LXC::Config->lock_config($vmid, $updatefn);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_snapshot_config',
    path => '{snapname}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get snapshot configuration",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot', 'VM.Snapshot.Rollback' ], any => 1],
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

	my $conf = PVE::LXC::Config->load_config($vmid);

	my $snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	delete $snap->{lxc};
	
	return $snap;
    }});

1;
