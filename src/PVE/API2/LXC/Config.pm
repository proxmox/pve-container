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
use PVE::HA::Config;
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

	my $conf = PVE::LXC::load_config($param->{vmid});

	delete $conf->{snapshots};
	delete $conf->{lxc};

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
    },
    parameters => {
    	additionalProperties => 0,
	properties => PVE::LXC::json_config_properties(
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

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, [@delete]);

	foreach my $opt (@delete) {
	    raise_param_exc({ delete => "you can't use '-$opt' and " .
				  "-delete $opt' at the same time" })
		if defined($param->{$opt});

	    if (!PVE::LXC::option_exists($opt)) {
		raise_param_exc({ delete => "unknown option '$opt'" });
	    }
	}

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, [keys %$param]);

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

my $query_loopdev = sub {
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
};

__PACKAGE__->register_method({
    name => 'resize_vm',
    path => '{vmid}/resize',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Resize a container mountpoint.",
    permissions => {
	check => ['perm', '/vms/{vmid}', $vm_config_perm_list, any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => PVE::LXC::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid }),
		disk => {
		    type => 'string',
		    description => "The disk you want to resize.",
		    enum => [PVE::LXC::mountpoint_names()],
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

	my $sizestr = extract_param($param, 'size');
	my $ext = ($sizestr =~ s/^\+//);
	my $newsize = PVE::JSONSchema::parse_size($sizestr);
	die "invalid size string" if !defined($newsize);

	die "no options specified\n" if !scalar(keys %$param);

	PVE::LXC::check_ct_modify_config_perm($rpcenv, $authuser, $vmid, undef, [keys %$param]);

	my $storage_cfg = cfs_read_file("storage.cfg");

	my $code = sub {

	    my $conf = PVE::LXC::load_config($vmid);
	    PVE::LXC::check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    my $running = PVE::LXC::check_running($vmid);

	    my $disk = $param->{disk};
	    my $mp = PVE::LXC::parse_ct_mountpoint($conf->{$disk});
	    my $volid = $mp->{volume};

	    my (undef, undef, $owner, undef, undef, undef, $format) =
		PVE::Storage::parse_volname($storage_cfg, $volid);

	    die "can't resize mountpoint owned by another container ($owner)"
		if $vmid != $owner;

	    die "can't resize volume: $disk if snapshot exists\n" 
		if %{$conf->{snapshots}} && $format eq 'qcow2';

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

	    my $size = PVE::Storage::volume_size_info($storage_cfg, $volid, 5);
	    $newsize += $size if $ext;
	    $newsize = int($newsize);

	    die "unable to shrink disk size\n" if $newsize < $size;

	    return if $size == $newsize;

	    PVE::Cluster::log_msg('info', $authuser, "update CT $vmid: resize --disk $disk --size $sizestr");

	    # FIXME: volume_resize doesn't do anything if $running=1?
	    PVE::Storage::volume_resize($storage_cfg, $volid, $newsize, 0);

	    $mp->{size} = $newsize;
	    $conf->{$disk} = PVE::LXC::print_ct_mountpoint($mp, $disk eq 'rootfs');

	    PVE::LXC::write_config($vmid, $conf);

	    if ($format eq 'raw') {
		my $path = PVE::Storage::path($storage_cfg, $volid, undef);
		if ($running) {
		    $path = &$query_loopdev($path);
		    die "internal error: CT running but mountpoint not attached to a loop device"
			if !$path; # fixme: zvols and other storages?
		    PVE::Tools::run_command(['losetup', '--set-capacity', $path]);

		    # In order for resize2fs to know that we need online-resizing a mountpoint needs
		    # to be visible to it in its namespace.
		    # To not interfere with the rest of the system we unshare the current mount namespace,
		    # mount over /tmp and then run resize2fs.

		    # interestingly we don't need to e2fsck on mounted systems...
		    my $quoted = PVE::Tools::shellquote($path);
		    my $cmd = "mount --make-rprivate / && mount $quoted /tmp && resize2fs $quoted";
		    PVE::Tools::run_command(['unshare', '-m', '--', 'sh', '-c', $cmd]);
		} else {
		    PVE::Tools::run_command(['e2fsck', '-f', '-y', $path]);
		    PVE::Tools::run_command(['resize2fs', $path]);
		}
	    }
	};

	PVE::LXC::lock_container($vmid, undef, $code);

	return undef;
    }});

1;
