package PVE::LXC::Setup;

use strict;
use warnings;

use POSIX;
use Cwd 'abs_path';

use PVE::Tools;

use PVE::LXC::Setup::Alpine;
use PVE::LXC::Setup::ArchLinux;
use PVE::LXC::Setup::CentOS;
use PVE::LXC::Setup::Debian;
use PVE::LXC::Setup::Devuan;
use PVE::LXC::Setup::Fedora;
use PVE::LXC::Setup::Gentoo;
use PVE::LXC::Setup::SUSE;
use PVE::LXC::Setup::Ubuntu;
use PVE::LXC::Setup::NixOS;
use PVE::LXC::Setup::Unmanaged;

my $plugins = {
    alpine    => 'PVE::LXC::Setup::Alpine',
    archlinux => 'PVE::LXC::Setup::ArchLinux',
    centos    => 'PVE::LXC::Setup::CentOS',
    debian    => 'PVE::LXC::Setup::Debian',
    devuan    => 'PVE::LXC::Setup::Devuan',
    fedora    => 'PVE::LXC::Setup::Fedora',
    gentoo    => 'PVE::LXC::Setup::Gentoo',
    opensuse  => 'PVE::LXC::Setup::SUSE',
    ubuntu    => 'PVE::LXC::Setup::Ubuntu',
    nixos     => 'PVE::LXC::Setup::NixOS',
    unmanaged => 'PVE::LXC::Setup::Unmanaged',
};

# a map to allow supporting related distro flavours
my $plugin_alias = {
    'opensuse-leap' => 'opensuse',
    'opensuse-tumbleweed' => 'opensuse',
    arch => 'archlinux',
    sles => 'opensuse',
};

my $autodetect_type = sub {
    my ($self, $rootdir, $os_release) = @_;

    if (my $id = $os_release->{ID}) {
	return $id if $plugins->{$id};
	return $plugin_alias->{$id} if $plugin_alias->{$id};
	warn "unknown ID '$id' in /etc/os-release file, trying fallback detection\n";
    }

    # fallback compatibility checks

    my $lsb_fn = "$rootdir/etc/lsb-release";
    if (-f $lsb_fn) {
	my $data =  PVE::Tools::file_get_contents($lsb_fn);
	if ($data =~ m/^DISTRIB_ID=Ubuntu$/im) {
	    return 'ubuntu';
	}
    }

    if (-f "$rootdir/etc/debian_version") {
	return "debian";
    } elsif (-f "$rootdir/etc/devuan_version") {
	return "devuan";
    } elsif (-f  "$rootdir/etc/SuSE-brand" || -f "$rootdir/etc/SuSE-release") {
	return "opensuse";
    } elsif (-f  "$rootdir/etc/fedora-release") {
	return "fedora";
    } elsif (-f  "$rootdir/etc/centos-release" || -f "$rootdir/etc/redhat-release") {
	return "centos";
    } elsif (-f  "$rootdir/etc/arch-release") {
	return "archlinux";
    } elsif (-f  "$rootdir/etc/alpine-release") {
	return "alpine";
    } elsif (-f  "$rootdir/etc/gentoo-release") {
	return "gentoo";
    } elsif (-d  "$rootdir/nix/store") {
	return "nixos";
    } elsif (-f "$rootdir/etc/os-release") {
	die "unable to detect OS distribution\n";
    } else {
	warn "/etc/os-release file not found and autodetection failed, falling back to 'unmanaged'\n";
	return "unmanaged";
    }
};

sub new {
    my ($class, $conf, $rootdir, $type) = @_;

    die "no root directory\n" if !$rootdir || $rootdir eq '/';

    my $self = bless { conf => $conf, rootdir => $rootdir}, $class;

    my $os_release = $self->get_ct_os_release();

    if ($conf->{ostype} && $conf->{ostype} eq 'unmanaged') {
	$type = 'unmanaged';
    } elsif (!defined($type)) {
	# try to autodetect type
	$type = &$autodetect_type($self, $rootdir, $os_release);
	my $expected_type = $conf->{ostype} || $type;

	if ($type ne $expected_type) {
	    warn "WARNING: /etc not present in CT, is the rootfs mounted?\n"
		if ! -e "$rootdir/etc";
	    warn "got unexpected ostype ($type != $expected_type)\n"
	}
    }

    my $plugin_class = $plugins->{$type} || die "no such OS type '$type'\n";

    my $plugin = $plugin_class->new($conf, $rootdir, $os_release);
    $self->{plugin} = $plugin;
    $self->{in_chroot} = 0;

    # Cache some host files we need access to:
    $plugin->{host_resolv_conf} = PVE::INotify::read_file('resolvconf');
    $plugin->{host_timezone} = PVE::INotify::read_file('timezone');

    abs_path('/etc/localtime') =~ m|^(/.+)| or die "invalid /etc/localtime\n"; # untaint
    $plugin->{host_localtime} = $1;

    # pass on user namespace information:
    my ($id_map, $root_uid, $root_gid) = PVE::LXC::parse_id_maps($conf);
    if (@$id_map) {
	$plugin->{id_map} = $id_map;
	$plugin->{root_uid} = $root_uid;
	$plugin->{root_gid} = $root_gid;
    }

    # if arch is unset, we try to autodetect it
    if (!defined($conf->{arch})) {
	my $arch = eval { $self->protected_call(sub { $plugin->detect_architecture() }) };

	if (my $err = $@) {
	    warn "Architecture detection failed: $err" if $err;
	}

	if (!defined($arch)) {
	    $arch = 'amd64';
	    print "Falling back to $arch.\nUse `pct set VMID --arch ARCH` to change.\n";
	} else {
	    print "Detected container architecture: $arch\n";
	}

	$conf->{arch} = $arch;
    }

    return $self;
}

# Forks into a chroot and executes $sub
sub protected_call {
    my ($self, $sub) = @_;

    # avoid recursion:
    return $sub->() if $self->{in_chroot};

    pipe(my $res_in, my $res_out) or die "pipe failed: $!\n";

    my $child = fork();
    die "fork failed: $!\n" if !defined($child);

    if (!$child) {
	close($res_in);
	# avoid recursive forks
	$self->{in_chroot} = 1;
	eval {
	    my $rootdir = $self->{rootdir};
	    chroot($rootdir) or die "failed to change root to: $rootdir: $!\n";
	    chdir('/') or die "failed to change to root directory\n";
	    my $res = $sub->();
	    if (defined($res)) {
		print {$res_out} "$res";
		$res_out->flush();
	    }
	};
	if (my $err = $@) {
	    warn $err;
	    POSIX::_exit(1);
	}
	POSIX::_exit(0);
    }
    close($res_out);
    my $result = do { local $/ = undef; <$res_in> };
    while (waitpid($child, 0) != $child) {}
    if ($? != 0) {
	my $method = (caller(1))[3];
	die "error in setup task $method\n";
    }
    return $result;
}

sub template_fixup {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->template_fixup($self->{conf}) });
}

sub setup_network {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->setup_network($self->{conf}) });
}

sub set_hostname {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->set_hostname($self->{conf}) });
}

sub set_dns {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->set_dns($self->{conf}) });
}

sub set_timezone {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->set_timezone($self->{conf}) });
}

sub setup_init {
    my ($self) = @_;
    $self->protected_call(sub { $self->{plugin}->setup_init($self->{conf}) });
}

sub set_user_password {
    my ($self, $user, $pw) = @_;
    $self->protected_call(sub { $self->{plugin}->set_user_password($self->{conf}, $user, $pw) });
}

my sub generate_ssh_key { # create temporary key in hosts' /run, then read and unlink
    my ($type, $comment) = @_;

    my $key_id = '';
    my $keygen_outfunc = sub {
	if ($_[0] =~ m/^((?:[0-9a-f]{2}:)+[0-9a-f]{2}|SHA256:[0-9a-z+\/]{43})\s+\Q$comment\E$/i) {
	    $key_id = $_[0];
	}
    };
    my $file = "/run/pve/.tmp$$.$type";
    PVE::Tools::run_command(
	['ssh-keygen', '-f', $file, '-t', $type, '-N', '', '-E', 'sha256', '-C', $comment],
	outfunc => $keygen_outfunc,
    );
    my ($private) = (PVE::Tools::file_get_contents($file) =~ /^(.*)$/sg); # untaint
    my ($public) = (PVE::Tools::file_get_contents("$file.pub") =~ /^(.*)$/sg); # untaint
    unlink $file, "$file.pub";

    return ($key_id, $private, $public);
}

sub rewrite_ssh_host_keys {
    my ($self) = @_;

    my $plugin = $self->{plugin};

    my $keynames = $plugin->ssh_host_key_types_to_generate();

    return if ! -d "$self->{rootdir}/etc/ssh" || !$keynames || !scalar(keys $keynames->%*);

    my $hostname = $self->{conf}->{hostname} || 'localhost';
    $hostname =~ s/\..*$//;

    my $keyfiles = [];
    for my $keytype (keys $keynames->%*) {
	my $basename = $keynames->{$keytype};
	print "Creating SSH host key '$basename' - this may take some time ...\n";
	my ($id, $private, $public) = generate_ssh_key($keytype, "root\@$hostname");
	print "done: $id\n";

	push $keyfiles->@*, ["/etc/ssh/$basename", $private, 0600], ["/etc/ssh/$basename.pub", $public, 0644];
    }

    $self->protected_call(sub { # write them now all to the CTs rootfs at once
	for my $file ($keyfiles->@*) {
	    $plugin->ct_file_set_contents($file->@*);
	}
    });
}

sub pre_start_hook {
    my ($self) = @_;

    $self->protected_call(sub { $self->{plugin}->pre_start_hook($self->{conf}) });
}

sub post_clone_hook {
    my ($self, $conf) = @_;

    $self->protected_call(sub { $self->{plugin}->post_clone_hook($conf) });
}

sub post_create_hook {
    my ($self, $root_password, $ssh_keys) = @_;

    $self->protected_call(sub {
	$self->{plugin}->post_create_hook($self->{conf}, $root_password, $ssh_keys);
    });
    $self->rewrite_ssh_host_keys();
}

sub unified_cgroupv2_support {
    my ($self) = @_;

    return $self->{plugin}->unified_cgroupv2_support($self->get_ct_init_path());
}

# os-release(5):
#   (...) a newline-separated list of environment-like shell-compatible
#   variable assignments. (...) beyond mere variable assignments, no shell
#   features are supported (this means variable expansion is explicitly not
#   supported) (...). Variable assignment values must be enclosed in double or
#   single quotes *if* they include spaces, semicolons or other special
#   characters outside of A-Z, a-z, 0-9. Shell special characters ("$", quotes,
#   backslash, backtick) must be escaped with backslashes (...). All strings
#   should be in UTF-8 format, and non-printable characters should not be used.
#   It is not supported to concatenate multiple individually quoted strings.
#   Lines beginning with "#" shall be ignored as comments.
my $parse_os_release = sub {
    my ($data) = @_;
    my $variables = {};
    while (defined($data) && $data =~ /^(.+)$/gm) {
	next if $1 !~ /^\s*([a-zA-Z_][a-zA-Z0-9_]*)=(.*)$/;
	my ($var, $content) = ($1, $2);
	chomp $content;

	if ($content =~ /^'([^']*)'/) {
	    $variables->{$var} = $1;
	} elsif ($content =~ /^"((?:[^"\\]|\\.)*)"/) {
	    my $s = $1;
	    $s =~ s/(\\["'`nt\$\\])/"\"$1\""/eeg;
	    $variables->{$var} = $s;
	} elsif ($content =~ /^([A-Za-z0-9]*)/) {
	    $variables->{$var} = $1;
	}
    }
    return $variables;
};

sub get_ct_os_release {
    my ($self) = @_;

    my $data = $self->protected_call(sub {
	if (-f '/etc/os-release') {
	    return PVE::Tools::file_get_contents('/etc/os-release');
	} elsif (-f '/usr/lib/os-release') {
	    return PVE::Tools::file_get_contents('/usr/lib/os-release');
	}
	return undef;
    });

    return &$parse_os_release($data);
}

# Checks whether /sbin/init is a symlink, and if it is, resolves it to the actual binary
sub get_ct_init_path {
    my ($self) = @_;

    my $init = $self->protected_call(sub {
	return $self->{plugin}->get_ct_init_path();
    });

    return $init;
}

1;
