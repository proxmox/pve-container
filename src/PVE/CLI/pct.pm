package PVE::CLI::pct;
    
use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::Cluster;
use PVE::INotify;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::CLIHandler;
use PVE::API2::LXC;
use PVE::API2::LXC::Config;
use PVE::API2::LXC::Status;
use PVE::API2::LXC::Snapshot;

use Data::Dumper;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit($status eq 'OK' ? 0 : -1);
};

__PACKAGE__->register_method ({
    name => 'console',
    path => 'console',
    method => 'GET',
    description => "Launch a console for the specified container.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	# test if container exists on this node
	my $conf = PVE::LXC::load_config($param->{vmid});

	my $cmd = PVE::LXC::get_console_command($param->{vmid}, $conf);
	exec(@$cmd);
    }});

__PACKAGE__->register_method ({
    name => 'enter',
    path => 'enter',
    method => 'GET',
    description => "Launch a shell for the specified container.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::LXC::complete_ctid_running }),
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	# test if container exists on this node
	PVE::LXC::load_config($param->{vmid});

	exec('lxc-attach', '-n',  $param->{vmid});
    }});

__PACKAGE__->register_method ({
    name => 'exec',
    path => 'exec',
    method => 'GET',
    description => "Launch a command inside the specified container.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid'),
	    'extra-args' => get_standard_option('extra-args'),
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	# test if container exists on this node
	PVE::LXC::load_config($param->{vmid});

	if (!@{$param->{'extra-args'}}) {
	    die "missing command";
	}
	exec('lxc-attach', '-n', $param->{vmid}, '--', @{$param->{'extra-args'}});
    }});

our $cmddef = {
    list=> [ 'PVE::API2::LXC', 'vmlist', [], { node => $nodename }, sub {
	my $res = shift;
	return if !scalar(@$res);
	my $format = "%-10s %-10s %-20s\n";
	printf($format, 'VMID', 'Status', 'Name');
	foreach my $d (sort {$a->{vmid} <=> $b->{vmid} } @$res) {
	    printf($format, $d->{vmid}, $d->{status}, $d->{name});
	}
    }],
    config => [ "PVE::API2::LXC::Config", 'vm_config', ['vmid'], 
		{ node => $nodename }, sub {
		    my $config = shift;
		    foreach my $k (sort (keys %$config)) {
			next if $k eq 'digest';
			my $v = $config->{$k};
			if ($k eq 'description') {
			    $v = PVE::Tools::encode_text($v);
			}
			print "$k: $v\n";
		    }
		}],
    set => [ 'PVE::API2::LXC::Config', 'update_vm', ['vmid'], { node => $nodename }],
    
    create => [ 'PVE::API2::LXC', 'create_vm', ['vmid', 'ostemplate'], { node => $nodename }, $upid_exit ],
    restore => [ 'PVE::API2::LXC', 'create_vm', ['vmid', 'ostemplate'], { node => $nodename, restore => 1 }, $upid_exit ],

    start => [ 'PVE::API2::LXC::Status', 'vm_start', ['vmid'], { node => $nodename }, $upid_exit],
    suspend => [ 'PVE::API2::LXC::Status', 'vm_suspend', ['vmid'], { node => $nodename }, $upid_exit],
    resume => [ 'PVE::API2::LXC::Status', 'vm_resume', ['vmid'], { node => $nodename }, $upid_exit],
    shutdown => [ 'PVE::API2::LXC::Status', 'vm_shutdown', ['vmid'], { node => $nodename }, $upid_exit],
    stop => [ 'PVE::API2::LXC::Status', 'vm_stop', ['vmid'], { node => $nodename }, $upid_exit],
    
    migrate => [ "PVE::API2::LXC", 'migrate_vm', ['vmid', 'target'], { node => $nodename }, $upid_exit],
    
    console => [ __PACKAGE__, 'console', ['vmid']],
    enter => [ __PACKAGE__, 'enter', ['vmid']],
    exec => [ __PACKAGE__, 'exec', ['vmid', 'extra-args']],
    
    destroy => [ 'PVE::API2::LXC', 'destroy_vm', ['vmid'], 
		 { node => $nodename }, $upid_exit ],

    snapshot => [ "PVE::API2::LXC::Snapshot", 'snapshot', ['vmid', 'snapname'],
		  { node => $nodename } , $upid_exit ],

    delsnapshot => [ "PVE::API2::LXC::Snapshot", 'delsnapshot', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],

    listsnapshot => [ "PVE::API2::LXC::Snapshot", 'list', ['vmid'], { node => $nodename },
		      sub {
			  my $res = shift;
			  foreach my $e (@$res) {
			      my $headline = $e->{description} || 'no-description';
			      $headline =~ s/\n.*//sg;
			      my $parent = $e->{parent} // 'no-parent';
			      printf("%-20s %-20s %s\n", $e->{name}, $parent, $headline);
			  }
		      }],

    rollback => [ "PVE::API2::LXC::Snapshot", 'rollback', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],

    template => [ "PVE::API2::LXC", 'template', ['vmid'], { node => $nodename }],
};


1;

__END__

=head1 NAME

pct - Tool to manage Linux Containers (LXC) on Proxmox VE

=head1 SYNOPSIS

=include synopsis

=head1 DESCRIPTION

pct is a tool to manages Linux Containers (LXC). You can create
and destroy containers, and control execution
(start/stop/suspend/resume). Besides that, you can use pct to set
parameters in the associated config file, like network configuration or
memory.

=head1 EXAMPLES

Create a container based on a Debian template
(provided you downloaded the template via the webgui before)

pct create 100 /var/lib/vz/template/cache/debian-8.0-standard_8.0-1_amd64.tar.gz

Start a container

pct start 100

Start a login session via getty

pct console 100

Enter the lxc namespace and run a shell as root user

pct enter 100

Display the configuration

pct config 100

Add a network interface called eth0, bridged to the host bridge vmbr0,
set the address and gateway, while it's running

pct set 100 -net0 name=eth0,bridge=vmbr0,ip=192.168.15.147/24,gw=192.168.15.1

Reduce the memory of the container to 512MB

pct set -memory 512 100

=head1 FILES

/etc/pve/lxc/<vmid>.conf

Configuration file for the container <vmid>

=head1 SEE ALSO

L<B<qm(1)>>, L<B<pvesh(1)>>

=include pve_copyright
