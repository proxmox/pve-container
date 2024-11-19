package PVE::API2::LXC::Config;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param run_command);
use PVE::Exception qw(raise raise_param_exc);
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::AccessControl;
use PVE::Firewall;
use PVE::GuestHelpers;
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::LXC::Create;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'vm_config',
    path => '',
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
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
	    current => {
		description => "Get current values (instead of pending values).",
		optional => 1,
		default => 0,
		type => 'boolean',
	    },
	    snapshot => get_standard_option('pve-snapshot-name', {
		description => "Fetch config values from given snapshot.",
		optional => 1,
		completion => sub {
		    my ($cmd, $pname, $cur, $args) = @_;
		    PVE::LXC::Config->snapshot_list($args->[0]);
		},
	    }),
	},
    },
    returns => {
	type => "object",
	properties => PVE::LXC::Config->json_config_properties({
	    lxc => {
		description => "Array of lxc low-level configurations ([[key1, value1], [key2, value2] ...]).",
		type => 'array',
		items => { type => 'array', items => { type => 'string' }},
		optional => 1,
	    },
	    digest => {
		type => 'string',
		description => 'SHA1 digest of configuration file. This can be used to prevent concurrent modifications.',
	    }
	}),
    },
    code => sub {
	my ($param) = @_;

	raise_param_exc({ snapshot => "cannot use 'snapshot' parameter with 'current'",
	                  current => "cannot use 'snapshot' parameter with 'current'"})
	    if ($param->{snapshot} && $param->{current});

	my $conf;
	if ($param->{snapshot}) {
	    $conf = PVE::LXC::Config->load_snapshot_config($param->{vmid}, $param->{snapshot});
	} else {
	    $conf = PVE::LXC::Config->load_current_config($param->{vmid}, $param->{current});
	}

	return $conf;
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
    path => '',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set container options.",
    permissions => {
	check => ['perm', '/vms/{vmid}', $vm_config_perm_list, any => 1],
	description => 'non-volume mount points in rootfs and mp[n] are restricted to root@pam',
    },
    parameters => {
	additionalProperties => 0,
	properties => PVE::LXC::Config->json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
		delete => {
		    type => 'string', format => 'pve-configid-list',
		    description => "A list of settings you want to delete.",
		    optional => 1,
		},
		revert => {
		    type => 'string', format => 'pve-configid-list',
		    description => "Revert a pending change.",
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
	my $revert_str = extract_param($param, 'revert');
	my @revert = PVE::Tools::split_list($revert_str);

	$param->{cpuunits} = PVE::CGroup::clamp_cpu_shares($param->{cpuunits})
	    if defined($param->{cpuunits}); # clamp value depending on cgroup version

	my $code = sub {

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    my $unprivileged = $conf->{unprivileged};
	    PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, $conf, {}, [@delete], $unprivileged);
	    PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, $conf, {}, [@revert], $unprivileged);

	    foreach my $opt (@revert) {
		raise_param_exc({ revert => "unknown option '$opt'" })
		    if !PVE::LXC::Config->option_exists($opt);

		raise_param_exc({ revert => "you can't use '-$opt' and '-revert $opt' at the same time" })
		    if defined($param->{$opt});
	    }

	    foreach my $opt (@delete) {
		raise_param_exc({ delete => "unknown option '$opt'" })
		    if !PVE::LXC::Config->option_exists($opt);

		raise_param_exc({ delete => "you can't use '-$opt' and -delete $opt' at the same time" })
		    if defined($param->{$opt});

		raise_param_exc({ delete => "you can't use '-delete $opt' and '-revert $opt' at the same time" })
		    if grep(/^$opt$/, @revert);
	    }

	    PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, $conf, $param, [], $unprivileged);

	    my $storage_cfg = PVE::Storage::config();

	    my $repl_conf = PVE::ReplicationConfig->new();
	    my $is_replicated = $repl_conf->check_for_existing_jobs($vmid, 1);
	    if ($is_replicated) {
		PVE::LXC::Config->foreach_volume($param, sub {
		    my ($opt, $mountpoint) = @_;
		    my $volid = $mountpoint->{volume};
		    return if !$volid || !($mountpoint->{replicate}//1);
		    if ($mountpoint->{type} eq 'volume') {
			my ($storeid, $format);
			if ($volid =~ $PVE::LXC::NEW_DISK_RE) {
			    $storeid = $1;
			    $format = $mountpoint->{format} || PVE::Storage::storage_default_format($storage_cfg, $storeid);
			} else {
			    ($storeid, undef) = PVE::Storage::parse_volume_id($volid, 1);
			    $format = (PVE::Storage::parse_volname($storage_cfg, $volid))[6];
			}
			return if PVE::Storage::storage_can_replicate($storage_cfg, $storeid, $format);
			my $scfg = PVE::Storage::storage_config($storage_cfg, $storeid);
			return if $scfg->{shared};
		    }
		    die "cannot add non-replicatable volume to a replicated VM\n";
		});
	    }

	    my $running = PVE::LXC::check_running($vmid);

	    my $errors = PVE::LXC::Config->update_pct_config($vmid, $conf, $running, $param, \@delete, \@revert);
	    # don't write to config if we get any errors – this can result in a broken config
	    raise_param_exc($errors) if scalar(keys %$errors);

	    PVE::LXC::Config->write_config($vmid, $conf);
	    $conf = PVE::LXC::Config->load_config($vmid);

	    PVE::LXC::update_lxc_config($vmid, $conf);
	    raise_param_exc($errors) if scalar(keys %$errors);
	};

	PVE::LXC::Config->lock_config($vmid, $code);

	return undef;
    }});

1;
