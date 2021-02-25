package PVE::API2::LXC;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param run_command);
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::RRD;
use PVE::DataCenterConfig;
use PVE::AccessControl;
use PVE::Firewall;
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::ReplicationConfig;
use PVE::LXC;
use PVE::LXC::Create;
use PVE::LXC::Migrate;
use PVE::GuestHelpers;
use PVE::VZDump::Plugin;
use PVE::API2::LXC::Config;
use PVE::API2::LXC::Status;
use PVE::API2::LXC::Snapshot;
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
	    properties => $PVE::LXC::vmstatus_return_properties,
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
	    unique => {
		optional => 1,
		type => 'boolean',
		description => "Assign a unique random ethernet address.",
		requires => 'restore',
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
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'number',
		minimum => '0',
		default => 'restore limit from datacenter or storage config',
	    },
	    start => {
		optional => 1,
		type => 'boolean',
		default => 0,
		description => "Start the CT after its creation finished successfully.",
	    },
	}),
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	PVE::Cluster::check_cfs_quorum();

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');
	my $ignore_unpack_errors = extract_param($param, 'ignore-unpack-errors');
	my $bwlimit = extract_param($param, 'bwlimit');
	my $start_after_create = extract_param($param, 'start');

	my $basecfg_fn = PVE::LXC::Config->config_file($vmid);
	my $same_container_exists = -f $basecfg_fn;

	# 'unprivileged' is read-only, so we can't pass it to update_pct_config
	my $unprivileged = extract_param($param, 'unprivileged');
	my $restore = extract_param($param, 'restore');
	my $unique = extract_param($param, 'unique');

	# used to skip firewall config restore if user lacks permission
	my $skip_fw_config_restore = 0;

	if ($restore) {
	    # fixme: limit allowed parameters
	}

	my $force = extract_param($param, 'force');

	if (!($same_container_exists && $restore && $force)) {
	    PVE::Cluster::check_vmid_unused($vmid);
	} else {
	    die "can't overwrite running container\n" if PVE::LXC::check_running($vmid);
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

	    # we don't want to restore a container-provided FW conf in this case
	    # since the user is lacking permission to configure the container's FW
	    $skip_fw_config_restore = 1;
	} else {
	    raise_perm_exc();
	}

	my $ostemplate = extract_param($param, 'ostemplate');
	my $storage = extract_param($param, 'storage') // 'local';

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, $pool, $param, []);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $archive;
	if ($ostemplate eq '-') {
	    die "pipe requires cli environment\n"
		if $rpcenv->{type} ne 'cli';
	    die "pipe can only be used with restore tasks\n"
		if !$restore;
	    $archive = '-';
	    die "restore from pipe requires rootfs parameter\n" if !defined($param->{rootfs});
	} else {
	    PVE::Storage::check_volume_access($rpcenv, $authuser, $storage_cfg, $vmid, $ostemplate);
	    $archive = $ostemplate;
	}

	my %used_storages;
	my $check_and_activate_storage = sub {
	    my ($sid) = @_;

	    my $scfg = PVE::Storage::storage_check_node($storage_cfg, $sid, $node);

	    raise_param_exc({ storage => "storage '$sid' does not support container directories"})
		if !$scfg->{content}->{rootdir};

	    $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

	    PVE::Storage::activate_storage($storage_cfg, $sid);
	    $used_storages{$sid} = 1;
	};

	my $conf = {};

	my $is_root = $authuser eq 'root@pam';

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

	die "mount points configured, but 'rootfs' not set - aborting\n"
	    if !$storage_only_mode && !defined($mp_param->{rootfs});

	# check storage access, activate storage
	my $delayed_mp_param = {};
	PVE::LXC::Config->foreach_volume($mp_param, sub {
	    my ($ms, $mountpoint) = @_;

	    my $volid = $mountpoint->{volume};
	    my $mp = $mountpoint->{mp};

	    if ($mountpoint->{type} ne 'volume') { # bind or device
		die "Only root can pass arbitrary filesystem paths.\n"
		    if !$is_root;
	    } else {
		my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
		&$check_and_activate_storage($sid);
	    }
	});

	# check/activate default storage
	&$check_and_activate_storage($storage) if !defined($mp_param->{rootfs});

	PVE::LXC::Config->update_pct_config($vmid, $conf, 0, $no_disk_param);

	$conf->{unprivileged} = 1 if $unprivileged;

	my $emsg = $restore ? "unable to restore CT $vmid -" : "unable to create CT $vmid -";

	eval { PVE::LXC::Config->create_and_lock_config($vmid, $force) };
	die "$emsg $@" if $@;

	my $code = sub {
	    my $old_conf = PVE::LXC::Config->load_config($vmid);
	    my $was_template;

	    my $vollist = [];
	    eval {
		my $orig_mp_param; # only used if $restore
		if ($restore) {
		    die "can't overwrite running container\n" if PVE::LXC::check_running($vmid);
		    if ($archive ne '-') {
			my $orig_conf;
			print "recovering backed-up configuration from '$archive'\n";
			($orig_conf, $orig_mp_param) = PVE::LXC::Create::recover_config($storage_cfg, $archive, $vmid);
			$was_template = delete $orig_conf->{template};
			# When we're root call 'restore_configuration' with restricted=0,
			# causing it to restore the raw lxc entries, among which there may be
			# 'lxc.idmap' entries. We need to make sure that the extracted contents
			# of the container match up with the restored configuration afterwards:
			$conf->{lxc} = $orig_conf->{lxc} if $is_root;

			$conf->{unprivileged} = $orig_conf->{unprivileged}
			    if !defined($unprivileged) && defined($orig_conf->{unprivileged});
		    }
		}
		if ($storage_only_mode) {
		    if ($restore) {
			if (!defined($orig_mp_param)) {
			    print "recovering backed-up configuration from '$archive'\n";
			    (undef, $orig_mp_param) = PVE::LXC::Create::recover_config($storage_cfg, $archive, $vmid);
			}
			$mp_param = $orig_mp_param;
			die "rootfs configuration could not be recovered, please check and specify manually!\n"
			    if !defined($mp_param->{rootfs});
			PVE::LXC::Config->foreach_volume($mp_param, sub {
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
				die "restoring '$ms' to $type mount is only possible for root\n"
				    if !$is_root;

				if ($mountpoint->{backup}) {
				    warn "WARNING - unsupported configuration!\n";
				    warn "backup was enabled for $type mount point $ms ('$mountpoint->{mp}')\n";
				    warn "mount point configuration will be restored after archive extraction!\n";
				    warn "contained files will be restored to wrong directory!\n";
				}
				delete $mp_param->{$ms}; # actually delay bind/dev mps
				$delayed_mp_param->{$ms} = PVE::LXC::Config->print_ct_mountpoint($mountpoint, $ms eq 'rootfs');
			    }
			});
		    } else {
			$mp_param->{rootfs} = "$storage:4"; # defaults to 4GB
		    }
		}

		$vollist = PVE::LXC::create_disks($storage_cfg, $vmid, $mp_param, $conf);

		# we always have the 'create' lock so check for more than 1 entry
		if (scalar(keys %$old_conf) > 1) {
		    # destroy old container volumes
		    PVE::LXC::destroy_lxc_container($storage_cfg, $vmid, $old_conf, { lock => 'create' });
		}

		eval {
		    my $rootdir = PVE::LXC::mount_all($vmid, $storage_cfg, $conf, 1);
		    $bwlimit = PVE::Storage::get_bandwidth_limit('restore', [keys %used_storages], $bwlimit);
		    print "restoring '$archive' now..\n"
			if $restore && $archive ne '-';
		    PVE::LXC::Create::restore_archive($storage_cfg, $archive, $rootdir, $conf, $ignore_unpack_errors, $bwlimit);

		    if ($restore) {
			print "merging backed-up and given configuration..\n";
			PVE::LXC::Create::restore_configuration($vmid, $storage_cfg, $archive, $rootdir, $conf, !$is_root, $unique, $skip_fw_config_restore);
			my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir);
			$lxc_setup->template_fixup($conf);
		    } else {
			my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir); # detect OS
			PVE::LXC::Config->write_config($vmid, $conf); # safe config (after OS detection)
			$lxc_setup->post_create_hook($password, $ssh_keys);
		    }
		};
		my $err = $@;
		PVE::LXC::umount_all($vmid, $storage_cfg, $conf, $err ? 1 : 0);
		PVE::Storage::deactivate_volumes($storage_cfg, PVE::LXC::Config->get_vm_volumes($conf));
		die $err if $err;
		# set some defaults
		$conf->{hostname} ||= "CT$vmid";
		$conf->{memory} ||= 512;
		$conf->{swap} //= 512;
		foreach my $mp (keys %$delayed_mp_param) {
		    $conf->{$mp} = $delayed_mp_param->{$mp};
		}
		# If the template flag was set, we try to convert again to template after restore
		if ($was_template) {
		    print STDERR "Convert restored container to template...\n";
		    PVE::LXC::template_create($vmid, $conf);
		    $conf->{template} = 1;
		}
		PVE::LXC::Config->write_config($vmid, $conf);
	    };
	    if (my $err = $@) {
		PVE::LXC::destroy_disks($storage_cfg, $vollist);
		eval { PVE::LXC::Config->destroy_config($vmid) };
		warn $@ if $@;
		die "$emsg $err";
	    }
	    PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;

	    PVE::API2::LXC::Status->vm_start({ vmid => $vmid, node => $node })
		if $start_after_create;
	};

	my $workername = $restore ? 'vzrestore' : 'vzcreate';
	my $realcmd = sub { PVE::LXC::Config->lock_config($vmid, $code); };

	return $rpcenv->fork_worker($workername, $vmid, $authuser, $realcmd);
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
	    { subdir => 'pending' },
	    { subdir => 'status' },
	    { subdir => 'vncproxy' },
	    { subdir => 'termproxy' },
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

	return PVE::RRD::create_rrd_graph(
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

	return PVE::RRD::create_rrd_data(
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
	    force => {
		type => 'boolean',
		description => "Force destroy, even if running.",
		default => 0,
		optional => 1,
	    },
	    purge => {
		type => 'boolean',
		description => "Remove container from all related configurations."
		    ." For example, backup jobs, replication jobs or HA."
		    ." Related ACLs and Firewall entries will *always* be removed.",
		default => 0,
		optional => 1,
	    },
	    'destroy-unreferenced-disks' => {
		type => 'boolean',
		description => "If set, destroy additionally all disks with the VMID from all"
		    ." enabled storages which are not referenced in the config.",
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
	my $vmid = $param->{vmid};

	# test if container exists

	my $conf = PVE::LXC::Config->load_config($vmid);
	my $early_checks = sub {
	    my ($conf) = @_;
	    PVE::LXC::Config->check_protection($conf, "can't remove CT $vmid");
	    PVE::LXC::Config->check_lock($conf);

	    my $ha_managed = PVE::HA::Config::service_is_configured("ct:$vmid");

	    if (!$param->{purge}) {
		die "unable to remove CT $vmid - used in HA resources and purge parameter not set.\n"
		    if $ha_managed;

		# do not allow destroy if there are replication jobs without purge
		my $repl_conf = PVE::ReplicationConfig->new();
		$repl_conf->check_for_existing_jobs($vmid);
	    }

	    return $ha_managed;
	};

	$early_checks->($conf);

	my $running_error_msg = "unable to destroy CT $vmid - container is running\n";
	die $running_error_msg if !$param->{force} && PVE::LXC::check_running($vmid); # check early

	my $code = sub {
	    # reload config after lock
	    $conf = PVE::LXC::Config->load_config($vmid);
	    my $ha_managed = $early_checks->($conf);

	    if (PVE::LXC::check_running($vmid)) {
		die $running_error_msg if !$param->{force};
		warn "forced to stop CT $vmid before destroying!\n";
		if (!$ha_managed) {
		    PVE::LXC::vm_stop($vmid, 1);
		} else {
		    run_command(['ha-manager', 'crm-command', 'stop',  "ct:$vmid", '120']);
		}
	    }

	    my $storage_cfg = cfs_read_file("storage.cfg");
	    PVE::LXC::destroy_lxc_container(
		$storage_cfg,
		$vmid,
		$conf,
		{ lock => 'destroyed' },
		$param->{'destroy-unreferenced-disks'},
	    );

	    PVE::AccessControl::remove_vm_access($vmid);
	    PVE::Firewall::remove_vmfw_conf($vmid);
	    if ($param->{purge}) {
	        print "purging CT $vmid from related configurations..\n";
		PVE::ReplicationConfig::remove_vmid_jobs($vmid);
		PVE::VZDump::Plugin::remove_vmid_from_backup_jobs($vmid);

		if ($ha_managed) {
		    PVE::HA::Config::delete_service_from_config("ct:$vmid");
		    print "NOTE: removed CT $vmid from HA resource configuration.\n";
		}
	    }

	    # only now remove the zombie config, else we can have reuse race
	    PVE::LXC::Config->destroy_config($vmid);
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
	    width => {
		optional => 1,
		description => "sets the width of the console in pixels.",
		type => 'integer',
		minimum => 16,
		maximum => 4096,
	    },
	    height => {
		optional => 1,
		description => "sets the height of the console in pixels.",
		type => 'integer',
		minimum => 16,
		maximum => 2160,
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
	    ['/usr/bin/ssh', '-e', 'none', '-t', $remip] : [];

	my $conf = PVE::LXC::Config->load_config($vmid, $node);
	my $concmd = PVE::LXC::get_console_command($vmid, $conf, -1);

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

	    if ($param->{width}) {
		push @$cmd, '-width', $param->{width};
	    }

	    if ($param->{height}) {
		push @$cmd, '-height', $param->{height};
	    }

	    if ($param->{websocket}) {
		$ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm
		push @$cmd, '-notls', '-listen', 'localhost';
	    }

	    push @$cmd, '-c', @$remcmd, @$shcmd;

	    run_command($cmd, keeplocale => 1);

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

__PACKAGE__->register_method ({
    name => 'termproxy',
    path => '{vmid}/termproxy',
    method => 'POST',
    protected => 1,
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Creates a TCP proxy connection.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
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

	my ($remip, $family);

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    ($remip, $family) = PVE::Cluster::remote_node_ip($node);
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	my $remcmd = $remip ?
	    ['/usr/bin/ssh', '-e', 'none', '-t', $remip, '--'] : [];

	my $conf = PVE::LXC::Config->load_config($vmid, $node);
	my $concmd = PVE::LXC::get_console_command($vmid, $conf, -1);

	my $shcmd = [ '/usr/bin/dtach', '-A',
		      "/var/run/dtach/vzctlconsole$vmid",
		      '-r', 'winch', '-z', @$concmd];

	my $realcmd = sub {
	    my $upid = shift;

	    syslog ('info', "starting lxc termproxy $upid\n");

	    my $cmd = ['/usr/bin/termproxy', $port, '--path', $authpath,
		       '--perm', 'VM.Console', '--'];
	    push @$cmd, @$remcmd, @$shcmd;

	    PVE::Tools::run_command($cmd);
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd, 1);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
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
	    force => {
		type => 'boolean',
		description => "Force migration despite local bind / device" .
		    " mounts. NOTE: deprecated, use 'shared' property of mount point instead.",
		optional => 1,
	    },
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'number',
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
	    die "can't migrate running container without --online or --restart\n"
		if !$param->{online} && !$param->{restart};
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "ct:$vmid";

		my $cmd = ['ha-manager', 'migrate', $service, $target];

		print "Requesting HA migration for CT $vmid to node $target\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hamigrate', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		PVE::LXC::Migrate->migrate($target, $targetip, $vmid, $param);
	    };

	    my $worker = sub {
		return PVE::GuestHelpers::guest_migration_lock($vmid, 10, $realcmd);
	    };

	    return $rpcenv->fork_worker('vzmigrate', $vmid, $authuser, $worker);
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
                enum => [ 'snapshot', 'clone', 'copy' ],
            },
            snapname => get_standard_option('pve-snapshot-name', {
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

		$conf->{template} = 1;

		PVE::LXC::Config->write_config($vmid, $conf);
		# and remove lxc config
		PVE::LXC::update_lxc_config($vmid, $conf);
	    };

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
	    snapname => get_standard_option('pve-snapshot-name', {
		optional => 1,
            }),
	    storage => get_standard_option('pve-storage-id', {
		description => "Target storage for full clone.",
		optional => 1,
	    }),
	    full => {
		optional => 1,
	        type => 'boolean',
	        description => "Create a full copy of all disks. This is always done when " .
		    "you clone a normal CT. For CT templates, we try to create a linked clone by default.",
	    },
	    target => get_standard_option('pve-node', {
		description => "Target node. Only allowed if the original VM is on shared storage.",
		optional => 1,
	    }),
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'number',
		minimum => '0',
		default => 'clone limit from datacenter or storage config',
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

	my $newid = extract_param($param, 'newid');

	my $pool = extract_param($param, 'pool');

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	}

	my $snapname = extract_param($param, 'snapname');

	my $storage = extract_param($param, 'storage');

	my $target = extract_param($param, 'target');

        my $localnode = PVE::INotify::nodename();

        undef $target if $target && ($target eq $localnode || $target eq 'localhost');

	PVE::Cluster::check_node_exists($target) if $target;

	my $storecfg = PVE::Storage::config();

	if ($storage) {
	    # check if storage is enabled on local node
	    PVE::Storage::storage_check_enabled($storecfg, $storage);
	    if ($target) {
		# check if storage is available on target node
		PVE::Storage::storage_check_node($storecfg, $storage, $target);
		# clone only works if target storage is shared
		my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		die "can't clone to non-shared storage '$storage'\n" if !$scfg->{shared};
	    }
	}

	PVE::Cluster::check_cfs_quorum();

	my $conffile;
	my $newconf = {};
	my $mountpoints = {};
	my $fullclone = {};
	my $vollist = [];
	my $running;

	PVE::LXC::Config->lock_config($vmid, sub {
	    my $src_conf = PVE::LXC::Config->set_lock($vmid, 'disk');

	    $running = PVE::LXC::check_running($vmid) || 0;

	    my $full = extract_param($param, 'full');
	    if (!defined($full)) {
		$full = !PVE::LXC::Config->is_template($src_conf);
	    }
	    die "parameter 'storage' not allowed for linked clones\n" if defined($storage) && !$full;

	    eval {
		die "snapshot '$snapname' does not exist\n"
		    if $snapname && !defined($src_conf->{snapshots}->{$snapname});


		my $src_conf = $snapname ? $src_conf->{snapshots}->{$snapname} : $src_conf;

		$conffile = PVE::LXC::Config->config_file($newid);
		die "unable to create CT $newid: config file already exists\n"
		    if -f $conffile;

		my $sharedvm = 1;
		foreach my $opt (keys %$src_conf) {
		    next if $opt =~ m/^unused\d+$/;

		    my $value = $src_conf->{$opt};

		    if (($opt eq 'rootfs') || ($opt =~ m/^mp\d+$/)) {
			my $mp = PVE::LXC::Config->parse_volume($opt, $value);

			if ($mp->{type} eq 'volume') {
			    my $volid = $mp->{volume};

			    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
			    $sid = $storage if defined($storage);
			    my $scfg = PVE::Storage::storage_config($storecfg, $sid);
			    if (!$scfg->{shared}) {
				$sharedvm = 0;
				warn "found non-shared volume: $volid\n" if $target;
			    }

			    $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

			    if ($full) {
				die "Cannot do full clones on a running container without snapshots\n"
				    if $running && !defined($snapname);
				$fullclone->{$opt} = 1;
			    } else {
				# not full means clone instead of copy
				die "Linked clone feature for '$volid' is not available\n"
				    if !PVE::Storage::volume_has_feature($storecfg, 'clone', $volid, $snapname, $running, {'valid_target_formats' => ['raw', 'subvol']});
			    }

			    $mountpoints->{$opt} = $mp;
			    push @$vollist, $volid;

			} else {
			    # TODO: allow bind mounts?
			    die "unable to clone mountpint '$opt' (type $mp->{type})\n";
			}
		    } elsif ($opt =~ m/^net(\d+)$/) {
			# always change MAC! address
			my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
			my $net = PVE::LXC::Config->parse_lxc_network($value);
			$net->{hwaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
			$newconf->{$opt} = PVE::LXC::Config->print_lxc_network($net);
		    } else {
			# copy everything else
			$newconf->{$opt} = $value;
		    }
		}
		die "can't clone CT to node '$target' (CT uses local storage)\n"
		    if $target && !$sharedvm;

		# Replace the 'disk' lock with a 'create' lock.
		$newconf->{lock} = 'create';

		delete $newconf->{snapshots};
		delete $newconf->{pending};
		delete $newconf->{template};
		if ($param->{hostname}) {
		    $newconf->{hostname} = $param->{hostname};
		}

		if ($param->{description}) {
		    $newconf->{description} = $param->{description};
		}

		# create empty/temp config - this fails if CT already exists on other node
		PVE::LXC::Config->write_config($newid, $newconf);
	    };
	    if (my $err = $@) {
		eval { PVE::LXC::Config->remove_lock($vmid, 'disk') };
		warn $@ if $@;
		die $err;
	    }
	});

	my $update_conf = sub {
	    my ($key, $value) = @_;
	    return PVE::LXC::Config->lock_config($newid, sub {
		my $conf = PVE::LXC::Config->load_config($newid);
		die "Lost 'create' config lock, aborting.\n"
		    if !PVE::LXC::Config->has_lock($conf, 'create');
		$conf->{$key} = $value;
		PVE::LXC::Config->write_config($newid, $conf);
	    });
	};

	my $realcmd = sub {
	    my ($upid) = @_;

	    my $newvollist = [];

	    my $verify_running = PVE::LXC::check_running($vmid) || 0;
	    die "unexpected state change\n" if $verify_running != $running;

	    eval {
		local $SIG{INT} =
		    local $SIG{TERM} =
		    local $SIG{QUIT} =
		    local $SIG{HUP} = sub { die "interrupted by signal\n"; };

		PVE::Storage::activate_volumes($storecfg, $vollist, $snapname);
		my $bwlimit = extract_param($param, 'bwlimit');

		foreach my $opt (keys %$mountpoints) {
		    my $mp = $mountpoints->{$opt};
		    my $volid = $mp->{volume};

		    my $newvolid;
		    if ($fullclone->{$opt}) {
			print "create full clone of mountpoint $opt ($volid)\n";
			my $source_storage = PVE::Storage::parse_volume_id($volid);
			my $target_storage = $storage // $source_storage;
			my $clonelimit = PVE::Storage::get_bandwidth_limit('clone', [$source_storage, $target_storage], $bwlimit);
			$newvolid = PVE::LXC::copy_volume($mp, $newid, $target_storage, $storecfg, $newconf, $snapname, $clonelimit);
		    } else {
			print "create linked clone of mount point $opt ($volid)\n";
			$newvolid = PVE::Storage::vdisk_clone($storecfg, $volid, $newid, $snapname);
		    }

		    push @$newvollist, $newvolid;
		    $mp->{volume} = $newvolid;

		    $update_conf->($opt, PVE::LXC::Config->print_ct_mountpoint($mp, $opt eq 'rootfs'));
		}

		PVE::AccessControl::add_vm_to_pool($newid, $pool) if $pool;
		PVE::LXC::Config->remove_lock($newid, 'create');

		if ($target) {
		    # always deactivate volumes - avoid lvm LVs to be active on several nodes
		    PVE::Storage::deactivate_volumes($storecfg, $vollist, $snapname) if !$running;
		    PVE::Storage::deactivate_volumes($storecfg, $newvollist);

		    my $newconffile = PVE::LXC::Config->config_file($newid, $target);
		    die "Failed to move config to node '$target' - rename failed: $!\n"
			if !rename($conffile, $newconffile);
		}
	    };
	    my $err = $@;

	    # Unlock the source config in any case:
	    eval { PVE::LXC::Config->remove_lock($vmid, 'disk') };
	    warn $@ if $@;

	    if ($err) {
		# Now cleanup the config & disks:
		unlink $conffile;

		sleep 1; # some storages like rbd need to wait before release volume - really?

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
    }});


__PACKAGE__->register_method({
    name => 'resize_vm',
    path => '{vmid}/resize',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Resize a container mount point.",
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
		enum => [PVE::LXC::Config->valid_volume_keys()],
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
	    my $mp = PVE::LXC::Config->parse_volume($disk, $conf->{$disk});

	    my $volid = $mp->{volume};

	    my (undef, undef, $owner, undef, undef, undef, $format) =
		PVE::Storage::parse_volname($storage_cfg, $volid);

	    die "can't resize mount point owned by another container ($owner)"
		if $vmid != $owner;

	    die "can't resize volume: $disk if snapshot exists\n"
		if %{$conf->{snapshots}} && $format eq 'qcow2';

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

	    PVE::Storage::activate_volumes($storage_cfg, [$volid]);

	    my $size = PVE::Storage::volume_size_info($storage_cfg, $volid, 5);

	    die "Could not determine current size of volume '$volid'\n" if !defined($size);

	    $newsize += $size if $ext;
	    $newsize = int($newsize);

	    die "unable to shrink disk size\n" if $newsize < $size;

	    die "disk is already at specified size\n" if $size == $newsize;

	    PVE::Cluster::log_msg('info', $authuser, "update CT $vmid: resize --disk $disk --size $sizestr");
	    my $realcmd = sub {
		# Note: PVE::Storage::volume_resize doesn't do anything if $running=1, so
		# we pass 0 here (parameter only makes sense for qemu)
		PVE::Storage::volume_resize($storage_cfg, $volid, $newsize, 0);

		$mp->{size} = $newsize;
		$conf->{$disk} = PVE::LXC::Config->print_ct_mountpoint($mp, $disk eq 'rootfs');

		PVE::LXC::Config->write_config($vmid, $conf);

		if ($format eq 'raw') {
		    # we need to ensure that the volume is mapped, if not needed this is a NOP
		    my $path = PVE::Storage::map_volume($storage_cfg, $volid);
		    $path = PVE::Storage::path($storage_cfg, $volid) if !defined($path);
		    if ($running) {

			$mp->{mp} = '/';
			my $use_loopdev = (PVE::LXC::mountpoint_mount_path($mp, $storage_cfg))[1];
			$path = PVE::LXC::query_loopdev($path) if $use_loopdev;
			die "internal error: CT running but mount point not attached to a loop device"
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

			# always un-map if not running, this is a NOP if not needed
			PVE::Storage::unmap_volume($storage_cfg, $volid);
		    }
		}
	    };

	    return $rpcenv->fork_worker('resize', $vmid, $authuser, $realcmd);
	};

	return PVE::LXC::Config->lock_config($vmid, $code);;
    }});

__PACKAGE__->register_method({
    name => 'move_volume',
    path => '{vmid}/move_volume',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Move a rootfs-/mp-volume to a different storage",
    permissions => {
	description => "You need 'VM.Config.Disk' permissions on /vms/{vmid}, " .
	    "and 'Datastore.AllocateSpace' permissions on the storage.",
	check =>
	[ 'and',
	  ['perm', '/vms/{vmid}', [ 'VM.Config.Disk' ]],
	  ['perm', '/storage/{storage}', [ 'Datastore.AllocateSpace' ]],
	],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    volume => {
		type => 'string',
		enum => [ PVE::LXC::Config->valid_volume_keys() ],
		description => "Volume which will be moved.",
	    },
	    storage => get_standard_option('pve-storage-id', {
		description => "Target Storage.",
		completion => \&PVE::Storage::complete_storage_enabled,
	    }),
	    delete => {
		type => 'boolean',
		description => "Delete the original volume after successful copy. By default the original is kept as an unused volume entry.",
		optional => 1,
		default => 0,
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    },
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'number',
		minimum => '0',
		default => 'clone limit from datacenter or storage config',
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

	my $vmid = extract_param($param, 'vmid');

	my $storage = extract_param($param, 'storage');

	my $mpkey = extract_param($param, 'volume');

	my $lockname = 'disk';

	my ($mpdata, $old_volid);

	PVE::LXC::Config->lock_config($vmid, sub {
	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    die "cannot move volumes of a running container\n" if PVE::LXC::check_running($vmid);

	    $mpdata = PVE::LXC::Config->parse_volume($mpkey, $conf->{$mpkey});
	    $old_volid = $mpdata->{volume};

	    die "you can't move a volume with snapshots and delete the source\n"
		if $param->{delete} && PVE::LXC::Config->is_volume_in_use_by_snapshots($conf, $old_volid);

	    PVE::Tools::assert_if_modified($param->{digest}, $conf->{digest});

	    PVE::LXC::Config->set_lock($vmid, $lockname);
	});

	my $realcmd = sub {
	    eval {
		PVE::Cluster::log_msg('info', $authuser, "move volume CT $vmid: move --volume $mpkey --storage $storage");

		my $conf = PVE::LXC::Config->load_config($vmid);
		my $storage_cfg = PVE::Storage::config();

		my $new_volid;

		eval {
		    PVE::Storage::activate_volumes($storage_cfg, [ $old_volid ]);
		    my $bwlimit = extract_param($param, 'bwlimit');
		    my $source_storage = PVE::Storage::parse_volume_id($old_volid);
		    my $movelimit = PVE::Storage::get_bandwidth_limit('move', [$source_storage, $storage], $bwlimit);
		    $new_volid = PVE::LXC::copy_volume($mpdata, $vmid, $storage, $storage_cfg, $conf, undef, $movelimit);
		    if (PVE::LXC::Config->is_template($conf)) {
			PVE::Storage::activate_volumes($storage_cfg, [ $new_volid ]);
			my $template_volid = PVE::Storage::vdisk_create_base($storage_cfg, $new_volid);
			$mpdata->{volume} = $template_volid;
		    } else {
			$mpdata->{volume} = $new_volid;
		    }

		    PVE::LXC::Config->lock_config($vmid, sub {
			my $digest = $conf->{digest};
			$conf = PVE::LXC::Config->load_config($vmid);
			PVE::Tools::assert_if_modified($digest, $conf->{digest});

			$conf->{$mpkey} = PVE::LXC::Config->print_ct_mountpoint($mpdata, $mpkey eq 'rootfs');

			PVE::LXC::Config->add_unused_volume($conf, $old_volid) if !$param->{delete};

			PVE::LXC::Config->write_config($vmid, $conf);
		    });

		    eval {
			# try to deactivate volumes - avoid lvm LVs to be active on several nodes
			PVE::Storage::deactivate_volumes($storage_cfg, [ $new_volid ])
		    };
		    warn $@ if $@;
		};
		if (my $err = $@) {
		    eval {
			PVE::Storage::vdisk_free($storage_cfg, $new_volid)
			    if defined($new_volid);
		    };
		    warn $@ if $@;
		    die $err;
		}

		if ($param->{delete}) {
		    eval {
			PVE::Storage::deactivate_volumes($storage_cfg, [ $old_volid ]);
			PVE::Storage::vdisk_free($storage_cfg, $old_volid);
		    };
		    if (my $err = $@) {
			warn $err;
			PVE::LXC::Config->lock_config($vmid, sub {
			    my $conf = PVE::LXC::Config->load_config($vmid);
			    PVE::LXC::Config->add_unused_volume($conf, $old_volid);
			    PVE::LXC::Config->write_config($vmid, $conf);
			});
		    }
		}
	    };
	    my $err = $@;
	    eval { PVE::LXC::Config->remove_lock($vmid, $lockname) };
	    warn $@ if $@;
	    die $err if $err;
	};
	my $task = eval {
	    $rpcenv->fork_worker('move_volume', $vmid, $authuser, $realcmd);
	};
	if (my $err = $@) {
	    eval { PVE::LXC::Config->remove_lock($vmid, $lockname) };
	    warn $@ if $@;
	    die $err;
	}
	return $task;
  }});

__PACKAGE__->register_method({
    name => 'vm_pending',
    path => '{vmid}/pending',
    method => 'GET',
    proxyto => 'node',
    description => 'Get container configuration, including pending changes.',
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		key => {
		    description => 'Configuration option name.',
		    type => 'string',
		},
		value => {
		    description => 'Current value.',
		    type => 'string',
		    optional => 1,
		},
		pending => {
		    description => 'Pending value.',
		    type => 'string',
		    optional => 1,
		},
		delete => {
		    description => "Indicates a pending delete request if present and not 0.",
		    type => 'integer',
		    minimum => 0,
		    maximum => 2,
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::LXC::Config->load_config($param->{vmid});

	my $pending_delete_hash = PVE::LXC::Config->parse_pending_delete($conf->{pending}->{delete});

	return PVE::GuestHelpers::config_with_pending_array($conf, $pending_delete_hash);
    }});

1;
