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
use PVE::Storage;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::LXC;
use PVE::LXC::Create;
use PVE::JSONSchema qw(get_standard_option);
use base qw(PVE::RESTHandler);

use Data::Dumper; # fixme: remove

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

	my $conf = PVE::LXC::Config->load_config($param->{vmid});

	delete $conf->{snapshots};

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

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, {}, [@delete]);

	foreach my $opt (@delete) {
	    raise_param_exc({ delete => "you can't use '-$opt' and " .
				  "-delete $opt' at the same time" })
		if defined($param->{$opt});

	    if (!PVE::LXC::Config->option_exists($opt)) {
		raise_param_exc({ delete => "unknown option '$opt'" });
	    }
	}

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, $param, []);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $repl_conf = PVE::ReplicationConfig->new();
	my $is_replicated = $repl_conf->check_for_existing_jobs($vmid, 1);
	if ($is_replicated) {
	    PVE::LXC::Config->foreach_mountpoint_full($param, 0, sub {
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

	my $code = sub {

	    my $conf = PVE::LXC::Config->load_config($vmid);
	    PVE::LXC::Config->check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    my $running = PVE::LXC::check_running($vmid);

	    PVE::LXC::Config->update_pct_config($vmid, $conf, $running, $param, \@delete);

	    PVE::LXC::Config->write_config($vmid, $conf);
	    PVE::LXC::update_lxc_config($vmid, $conf);
	};

	PVE::LXC::Config->lock_config($vmid, $code);

	return undef;
    }});

1;
