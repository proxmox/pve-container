package PVE::LXC::Setup;

use strict;
use warnings;
use POSIX;
use PVE::Tools;

use PVE::LXC::Setup::Debian;
use PVE::LXC::Setup::Ubuntu;
use PVE::LXC::Setup::Redhat;
use PVE::LXC::Setup::ArchLinux;

my $plugins = {
    debian    => 'PVE::LXC::Setup::Debian',
    ubuntu    => 'PVE::LXC::Setup::Ubuntu',
    redhat    => 'PVE::LXC::Setup::Redhat',
    archlinux => 'PVE::LXC::Setup::ArchLinux',
};

my $autodetect_type = sub {
    my ($rootdir) = @_;

    my $lsb_fn = "$rootdir/etc/lsb-release";
    if (-f $lsb_fn) {
	my $data =  PVE::Tools::file_get_contents($lsb_fn);
	if ($data =~ m/^DISTRIB_ID=Ubuntu$/im) {
	    return 'ubuntu';
	}
    }

    if (-f "$rootdir/etc/debian_version") {
	return "debian";
    } elsif (-f  "$rootdir/etc/redhat-release") {
	return "redhat";
    } elsif (-f  "$rootdir/etc/arch-release") {
	return "archlinux";
    }

    die "unable to detect OS disribution\n";
};

sub new {
    my ($class, $conf, $rootdir, $type) = @_;

    die "no root directory\n" if !$rootdir || $rootdir eq '/';

    my $self = bless { conf => $conf, rootdir => $rootdir};

    if (!defined($type)) {
	# try to autodetect type
	$type = &$autodetect_type($rootdir);
    }
    
    my $plugin_class = $plugins->{$type} ||
	"no such OS type '$type'\n";

    my $plugin = $plugin_class->new($conf, $rootdir);
    $self->{plugin} = $plugin;
    $self->{in_chroot} = 0;

    # Cache some host files we need access to:
    $plugin->{host_resolv_conf} = PVE::INotify::read_file('resolvconf');

    # pass on user namespace information:
    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    if (@$id_map) {
	$plugin->{id_map} = $id_map;
	$plugin->{rootuid} = $rootuid;
	$plugin->{rootgid} = $rootgid;
    }
    
    return $self;
}

sub protected_call {
    my ($self, $sub) = @_;

    # avoid recursion:
    return $sub->() if $self->{in_chroot};

    my $rootdir = $self->{rootdir};
    if (!-d "$rootdir/dev" && !mkdir("$rootdir/dev")) {
	die "failed to create temporary /dev directory: $!\n";
    }

    my $child = fork();
    die "fork failed: $!\n" if !defined($child);

    if (!$child) {
	# avoid recursive forks
	$self->{in_chroot} = 1;
	$self->{plugin}->{in_chroot} = 1;
	eval {
	    chroot($rootdir) or die "failed to change root to: $rootdir: $!\n";
	    chdir('/') or die "failed to change to root directory\n";
	    $sub->();
	};
	if (my $err = $@) {
	    warn $err;
	    POSIX::_exit(1);
	}
	POSIX::_exit(0);
    }
    while (waitpid($child, 0) != $child) {}
    if ($? != 0) {
	my $method = (caller(1))[3];
	die "error in setup task $method\n";
    }
}

sub template_fixup {
    my ($self) = @_;

    my $code = sub {
	$self->{plugin}->template_fixup($self->{conf});
    };
    $self->protected_call($code);
}
 
sub setup_network {
    my ($self) = @_;

    my $code = sub {
	$self->{plugin}->setup_network($self->{conf});
    };
    $self->protected_call($code);
}

sub set_hostname {
    my ($self) = @_;

    my $code = sub {
	$self->{plugin}->set_hostname($self->{conf});
    };
    $self->protected_call($code);
}

sub set_dns {
    my ($self) = @_;

    my $code = sub {
	$self->{plugin}->set_dns($self->{conf});
    };
    $self->protected_call($code);
}

sub setup_init {
    my ($self) = @_;

    my $code = sub {
	$self->{plugin}->setup_init($self->{conf});
    };
    $self->protected_call($code);
}

sub set_user_password {
    my ($self, $user, $pw) = @_;
    
    my $code = sub {
	$self->{plugin}->set_user_password($self->{conf}, $user, $pw);
    };
    $self->protected_call($code);
}

sub rewrite_ssh_host_keys {
    my ($self) = @_;

    my $conf = $self->{conf};
    my $plugin = $self->{plugin};
    my $rootdir = $self->{rootdir};

    return if ! -d "$rootdir/etc/ssh";

    my $keynames = {
	rsa1 => 'ssh_host_key',
	rsa => 'ssh_host_rsa_key',
	dsa => 'ssh_host_dsa_key',
	ecdsa => 'ssh_host_ecdsa_key', 
	ed25519 => 'ssh_host_ed25519_key',
    };

    my $hostname = $conf->{hostname} || 'localhost';
    $hostname =~ s/\..*$//;

    # Create temporary keys in /tmp on the host

    my $keyfiles = {};
    foreach my $keytype (keys %$keynames) {
	my $basename = $keynames->{$keytype};
	my $file = "/tmp/$$.$basename";
	print "Creating SSH host key '$basename' - this may take some time ...\n";
	my $cmd = ['ssh-keygen', '-q', '-f', $file, '-t', $keytype,
		   '-N', '', '-C', "root\@$hostname"];
	PVE::Tools::run_command($cmd);
	$keyfiles->{"/etc/ssh/$basename"} = [PVE::Tools::file_get_contents($file), 0600];
	$keyfiles->{"/etc/ssh/$basename.pub"} = [PVE::Tools::file_get_contents("$file.pub"), 0644];
	unlink $file;
	unlink "$file.pub";
    }

    # Write keys out in a protected call

    my $code = sub {
	foreach my $file (keys %$keyfiles) {
	    $plugin->ct_file_set_contents($file, @{$keyfiles->{$file}});
	}
    };
    $self->protected_call($code);
}    

sub pre_start_hook {
    my ($self) = @_;

    my $code = sub {
	# Create /fastboot to skip run fsck
	$self->{plugin}->ct_file_set_contents('/fastboot', '');

	$self->{plugin}->pre_start_hook($self->{conf});
    };
    $self->protected_call($code);
}

sub post_create_hook {
    my ($self, $root_password) = @_;

    my $code = sub {
	$self->{plugin}->post_create_hook($self->{conf}, $root_password);
    };
    $self->protected_call($code);
    $self->rewrite_ssh_host_keys();
}

1;
