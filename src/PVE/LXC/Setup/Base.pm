package PVE::LXC::Setup::Base;

use strict;
use warnings;

use Cwd 'abs_path';
use File::stat;
use Digest::SHA;
use IO::File;
use Encode;
use Fcntl;
use File::Path;
use File::Spec;
use File::Basename;
use POSIX ();

use PVE::INotify;
use PVE::Tools;
use PVE::Network;

use PVE::LXC::Setup::Plugin;
use base qw(PVE::LXC::Setup::Plugin);

sub new {
    my ($class, $conf, $rootdir, $os_release) = @_;

    return bless { conf => $conf, rootdir => $rootdir, os_release => $os_release }, $class;
}

sub lookup_dns_conf {
    my ($self, $conf) = @_;

    my $nameserver = $conf->{nameserver};
    my $searchdomains = $conf->{searchdomain};

    if ($conf->{'testmode'}) {
	$nameserver //= '8.8.8.8 8.8.8.9';
	$searchdomains //= 'proxmox.com';
    }

    my $host_resolv_conf = $self->{host_resolv_conf};

    if (!defined($nameserver)) {
	my @list = ();
	foreach my $k ("dns1", "dns2", "dns3") {
	    if (my $ns = $host_resolv_conf->{$k}) {
		push @list, $ns;
	    }
	}
	$nameserver = join(' ', @list);
    }

    if (!defined($searchdomains)) {
	$searchdomains = $host_resolv_conf->{search};
    }

    return ($searchdomains, $nameserver);
}

sub update_etc_hosts {
    my ($self, $hostip, $oldname, $newname, $searchdomains) = @_;

    my $hosts_fn = '/etc/hosts';
    return if $self->ct_is_file_ignored($hosts_fn);

    my $namepart = ($newname =~ s/\..*$//r);

    my $all_names = '';
    if ($newname =~ /\./) {
	$all_names .= "$newname $namepart";
    } else {
	foreach my $domain (PVE::Tools::split_list($searchdomains)) {
	    $all_names .= ' ' if $all_names;
	    $all_names .= "$newname.$domain";
	}
	$all_names .= ' ' if $all_names;
	$all_names .= $newname;
    }

    # Prepare section:
    my $section = '';

    my $lo4 = "127.0.0.1 localhost.localnet localhost\n";
    my $lo6 = "::1 localhost.localnet localhost\n";
    if ($self->ct_file_exists($hosts_fn)) {
	my $data = $self->ct_file_get_contents($hosts_fn);
	# don't take localhost entries within our hosts sections into account
	$data = remove_pve_sections($data);

	# check for existing localhost entries
	$section .= $lo4 if $data !~ /^\h*127\.0\.0\.1\h+/m;
	$section .= $lo6 if $data !~ /^\h*::1\h+/m;
    } else {
	$section .= $lo4 . $lo6;
    }

    if (defined($hostip)) {
	$section .= "$hostip $all_names\n";
    } elsif ($namepart ne 'localhost') {
	$section .= "127.0.1.1 $all_names\n";
    } else {
	$section .= "127.0.1.1 $namepart\n";
    }

    $self->ct_modify_file($hosts_fn, $section);
}

sub template_fixup {
    my ($self, $conf) = @_;

    # do nothing by default
}

sub set_dns {
    my ($self, $conf) = @_;

    my ($searchdomains, $nameserver) = $self->lookup_dns_conf($conf);
    
    my $data = '';

    $data .= "search " . join(' ', PVE::Tools::split_list($searchdomains)) . "\n"
	if $searchdomains;

    foreach my $ns ( PVE::Tools::split_list($nameserver)) {
	$data .= "nameserver $ns\n";
    }

    $self->ct_modify_file("/etc/resolv.conf", $data, replace => 1);
}

sub set_hostname {
    my ($self, $conf) = @_;
    
    my $hostname = $conf->{hostname} || 'localhost';

    my $namepart = ($hostname =~ s/\..*$//r);

    my $hostname_fn = "/etc/hostname";
    
    my $oldname = $self->ct_file_read_firstline($hostname_fn) || 'localhost';

    my ($ipv4, $ipv6) = PVE::LXC::get_primary_ips($conf);
    my $hostip = $ipv4 || $ipv6;

    my ($searchdomains) = $self->lookup_dns_conf($conf);

    $self->update_etc_hosts($hostip, $oldname, $hostname, $searchdomains);
    
    $self->ct_file_set_contents($hostname_fn, "$namepart\n");
}

sub setup_network {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

sub setup_init {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

# A few distros as well as unprivileged containers cannot deal with the
# /dev/lxc/ tty subdirectory.
sub devttydir {
    my ($self, $conf) = @_;
    return $conf->{unprivileged} ? '' : 'lxc/';
}

sub fixup_old_getty {
    my ($self) = @_;

    my $sd_dir_rel = $self->ct_is_executable("/lib/systemd/systemd") ?
	"/lib/systemd/system" : "/usr/lib/systemd/system";

    my $sd_getty_service_rel = "$sd_dir_rel/getty\@.service";
    return if !$self->ct_file_exists($sd_getty_service_rel);

    my $raw = $self->ct_file_get_contents($sd_getty_service_rel);

    my $sd_container_getty_service_rel = "$sd_dir_rel/container-getty\@.service";
    # systemd on CenoOS 7.1 is too old (version 205), so there is no
    # container-getty service
    if (!$self->ct_file_exists($sd_container_getty_service_rel)) {
	if ($raw =~ s!^ConditionPathExists=/dev/tty0$!ConditionPathExists=/dev/tty!m) {
	    $self->ct_file_set_contents($sd_getty_service_rel, $raw);
	}
    } else {
	# undo above change (in case someone updated systemd)
	if ($raw =~ s!^ConditionPathExists=/dev/tty$!ConditionPathExists=/dev/tty0!m) {
	    $self->ct_file_set_contents($sd_getty_service_rel, $raw);
	}
    }
}

sub setup_container_getty_service {
    my ($self, $conf) = @_;

    my $sd_dir = $self->ct_is_executable("/lib/systemd/systemd") ?
	"/lib/systemd/system" : "/usr/lib/systemd/system";

    # prefer container-getty.service shipped by newer systemd versions
    # fallback to getty.service and just return if that doesn't exists either..
    my $template_base = "container-getty\@";
    my $template_path = "${sd_dir}/${template_base}.service";
    my $instance_base = $template_base;

    if (!$self->ct_file_exists($template_path)) {
	$template_base = "getty\@";
	$template_path = "${template_base}.service";
	$instance_base = "{$template_base}tty";
	return if !$self->ct_file_exists($template_path);
    }

    my $raw = $self->ct_file_get_contents($template_path);
    my $ttyname = $self->devttydir($conf) . 'tty%I';
    if ($raw =~ s@pts/%I|lxc/tty%I@$ttyname@g) {
	$self->ct_file_set_contents($template_path, $raw);
    }

    my $getty_target_fn = "/etc/systemd/system/getty.target.wants/";
    my $ttycount = PVE::LXC::Config->get_tty_count($conf);

    for (my $i = 1; $i < 7; $i++) {
	# ensure that not two gettys are using the same tty!
	$self->ct_unlink("$getty_target_fn/getty\@tty$i.service");
	$self->ct_unlink("$getty_target_fn/container-getty\@$i.service");

	# re-enable only those requested
	if ($i <= $ttycount) {
	    my $tty_service = "${instance_base}${i}.service";

	    $self->ct_symlink($template_path, "$getty_target_fn/$tty_service");
	}
    }

    # ensure getty.target is not masked
    $self->ct_unlink("/etc/systemd/system/getty.target");
}

sub setup_systemd_networkd {
    my ($self, $conf) = @_;

    foreach my $k (keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $d = PVE::LXC::Config->parse_lxc_network($conf->{$k});
	next if !$d->{name};

	my $filename = "/etc/systemd/network/$d->{name}.network";

	my $data = <<"DATA";
[Match]
Name = $d->{name}

[Network]
Description = Interface $d->{name} autoconfigured by PVE
DATA

	my $routes = '';
	my ($has_ipv4, $has_ipv6);

	# DHCP bitflags:
	my @DHCPMODES = ('no', 'ipv4', 'ipv6', 'yes');
	my ($NONE, $DHCP4, $DHCP6, $BOTH) = (0, 1, 2, 3);
	my $dhcp = $NONE;
	my $accept_ra = 'false';

	if (defined(my $ip = $d->{ip})) {
	    if ($ip eq 'dhcp') {
		$dhcp |= $DHCP4;
	    } elsif ($ip ne 'manual') {
		$has_ipv4 = 1;
		$data .= "Address = $ip\n";
	    }
	}
	if (defined(my $gw = $d->{gw})) {
	    $data .= "Gateway = $gw\n";
	    if ($has_ipv4 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip}, 4)) {
		$routes .= "\n[Route]\nDestination = $gw/32\nScope = link\n";
	    }
	}

	if (defined(my $ip = $d->{ip6})) {
	    if ($ip eq 'dhcp') {
		$dhcp |= $DHCP6;
	    } elsif ($ip eq 'auto') {
		$accept_ra = 'true';
	    } elsif ($ip ne 'manual') {
		$has_ipv6 = 1;
		$data .= "Address = $ip\n";
	    }
	}
	if (defined(my $gw = $d->{gw6})) {
	    $accept_ra = 'false';
	    $data .= "Gateway = $gw\n";
	    if ($has_ipv6 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip6}, 6) &&
		!PVE::Network::is_ip_in_cidr($gw, 'fe80::/10', 6)) {
		$routes .= "\n[Route]\nDestination = $gw/128\nScope = link\n";
	    }
	}

	$data .= "DHCP = $DHCPMODES[$dhcp]\n";
	$data .= "IPv6AcceptRA = $accept_ra\n";
	$data .= $routes if $routes;

	$self->ct_file_set_contents($filename, $data);
    }
}

sub setup_securetty {
    my ($self, $conf, @add) = @_;

    my $filename = "/etc/securetty";
    # root login is already allowed on every device if no securetty present
    return if !$self->ct_file_exists($filename);

    if (!scalar(@add)) {
	@add = qw(console tty1 tty2 tty3 tty4);
	if (my $dir = $self->devttydir($conf)) {
	    @add = map { "${dir}$_" } @add;
	}
    }

    my $data = $self->ct_file_get_contents($filename);
    chomp $data; $data .= "\n";
    foreach my $dev (@add) {
	if ($data !~ m!^\Q$dev\E\s*$!m) {
	    $data .= "$dev\n"; 
	}
    }
    $self->ct_file_set_contents($filename, $data);
}

my $replacepw  = sub {
    my ($self, $file, $user, $epw, $shadow) = @_;

    my $tmpfile = "$file.$$";

    eval  {
	my $src = $self->ct_open_file_read($file) ||
	    die "unable to open file '$file' - $!";

	my $st = $self->ct_stat($src) ||
	    die "unable to stat file - $!";

	my $dst = $self->ct_open_file_write($tmpfile) ||
	    die "unable to open file '$tmpfile' - $!";

	# copy owner and permissions
	chmod $st->mode, $dst;
	chown $st->uid, $st->gid, $dst;

	my $last_change = int(time()/(60*60*24));

	while (defined (my $line = <$src>)) {
	    if ($shadow) {
		$line =~ s/^${user}:[^:]*:[^:]*:/${user}:${epw}:${last_change}:/;
	    } else {
		$line =~ s/^${user}:[^:]*:/${user}:${epw}:/;
	    }
	    print $dst $line;
	}

	$src->close() || die "close '$file' failed - $!\n";
	$dst->close() || die "close '$tmpfile' failed - $!\n";
    };
    if (my $err = $@) {
	$self->ct_unlink($tmpfile);
    } else {
	$self->ct_rename($tmpfile, $file);
	$self->ct_unlink($tmpfile); # in case rename fails
    }	
};

sub set_user_password {
    my ($self, $conf, $user, $opt_password) = @_;

    my $pwfile = "/etc/passwd";

    return if !$self->ct_file_exists($pwfile);

    my $shadow = "/etc/shadow";
    
    if (defined($opt_password)) {
	if ($opt_password !~ m/^\$(?:1|2[axy]?|5|6)\$[a-zA-Z0-9.\/]{1,16}\$[a-zA-Z0-9.\/]+$/) {
	    my $time = substr (Digest::SHA::sha1_base64 (time), 0, 8);
	    $opt_password = crypt(encode("utf8", $opt_password), "\$6\$$time\$");
	};
    } else {
	$opt_password = '*';
    }
    
    if ($self->ct_file_exists($shadow)) {
	&$replacepw ($self, $shadow, $user, $opt_password, 1);
	&$replacepw ($self, $pwfile, $user, 'x');
    } else {
	&$replacepw ($self, $pwfile, $user, $opt_password);
    }
}

my $parse_home_dir = sub {
    my ($self, $passwdfile, $user) = @_;

    my $fh = $self->ct_open_file_read($passwdfile);
    while (defined (my $line = <$fh>)) {
	return $2
	    if $line =~ m/^${user}:([^:]*:){4}([^:]*):/;
    }
};

sub set_user_authorized_ssh_keys {
    my ($self, $conf, $user, $ssh_keys) = @_;

    my $passwd = "/etc/passwd";
    my $home = $user eq "root" ? "/root/" : "/home/$user/";

    $home = &$parse_home_dir($self, $passwd, $user)
	if $self->ct_file_exists($passwd);

    die "home directory '$home' of $user does not exist!"
	if ! ($self->ct_is_directory($home) || $self->ct_is_symlink($home));

    $self->ct_mkdir("$home/.ssh", 0700)
	if ! $self->ct_is_directory("$home/.ssh");

    $self->ct_modify_file("$home/.ssh/authorized_keys", $ssh_keys, perms => 0700);
}

my $randomize_crontab = sub {
    my ($self, $conf) = @_;

    my @files;
    # Note: dir_glob_foreach() untaints filenames!
    PVE::Tools::dir_glob_foreach("/etc/cron.d", qr/[A-Z\-\_a-z0-9]+/, sub {
	my ($name) = @_;
	push @files, "/etc/cron.d/$name";
    });

    my $crontab_fn = "/etc/crontab";
    unshift @files, $crontab_fn if $self->ct_file_exists($crontab_fn);
    
    foreach my $filename (@files) {
	my $data = $self->ct_file_get_contents($filename);
 	my $new = '';
	foreach my $line (split(/\n/, $data)) {
	    # we only randomize minutes for root crontab entries
	    if ($line =~ m/^\d+(\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S.*)$/) {
		my $rest = $1;
		my $min = int(rand()*59);
		$new .= "$min$rest\n";
	    } else {
		$new .= "$line\n";
	    }
	}
	$self->ct_file_set_contents($filename, $new);
   }
};

sub set_timezone {
    my ($self, $conf) = @_;

    my $zoneinfo = $conf->{timezone};

    return if !defined($zoneinfo);

    my $tz_path = "/usr/share/zoneinfo/$zoneinfo";

    if ($zoneinfo eq 'host') {
	$tz_path = $self->{host_localtime};
    }

    if ($self->ct_file_exists($tz_path)) {
	if (abs_path('/etc/localtime') ne $tz_path) {
	    my $tmpfile = "localtime.$$.new.tmpfile";
	    $self->ct_symlink($tz_path, $tmpfile);
	    $self->ct_rename($tmpfile, "/etc/localtime");
	}

	# not all distributions have /etc/timezone
	if ($self->ct_file_exists('/etc/timezone')) {
	    my $contents = $zoneinfo eq 'host' ? $self->{host_timezone} : $zoneinfo;
	    $self->ct_file_set_contents('/etc/timezone', "$contents\n");
	}
    } else {
	warn "container does not have $tz_path, timezone can not be modified\n";
    }
}

sub clear_machine_id {
    my ($self, $conf, $clone) = @_;

    my $uses_systemd = $self->ct_is_executable("/lib/systemd/systemd")
	|| $self->ct_is_executable("/usr/lib/systemd/systemd");

    my $dbus_machine_id_path = "/var/lib/dbus/machine-id";
    my $machine_id_path = "/etc/machine-id";

    my $machine_id_existed = $self->ct_file_exists($machine_id_path);

    if (
	$self->ct_file_exists($dbus_machine_id_path)
	&& !$self->ct_is_symlink($dbus_machine_id_path)
	&& $uses_systemd
    ) {
        $self->ct_unlink($dbus_machine_id_path);
    }

    if ($machine_id_existed) {
	# truncate exiting ones on clone to avoid FirstBoot condition. admins can override this by
	# removing the machine-id file or setting it to uninitialized before creating a template, or
	# cloning a guest - as per machine-id(5) man page. TODO: add explicit switch to API?
	if ($clone) {
	    my $old_machine_id = $self->ct_file_read_firstline($machine_id_path) // '';
	    if ($uses_systemd && $old_machine_id ne 'uninitialized') {
		$self->ct_file_set_contents($machine_id_path, "\n") if $uses_systemd;
	    }
	} else {
	    $self->ct_unlink($machine_id_path);
	}
    }
}

# tries to guess the systemd (major) version based on the
# libsystemd-shared<version>.so linked with /sbin/init
sub get_systemd_version {
    my ($self, $init) = @_;

    my $version = undef;
    PVE::Tools::run_command(
	['objdump', '-p', $self->{rootdir}.$init],
	outfunc => sub {
	    my $line = shift;
	    if ($line =~ /libsystemd-shared-(\d+)(?:[-.][a-zA-Z0-9]+)*\.so:?$/) {
		$version = $1;
	    }
	},
	errmsg => "objdump on $init failed",
    );

    return $version;
}

sub unified_cgroupv2_support {
    my ($self, $init) = @_;

    # https://www.freedesktop.org/software/systemd/man/systemd.html
    # systemd is installed as symlink to /sbin/init
    # assume non-systemd init will run with unified cgroupv2
    if (!defined($init) || $init !~ m@/systemd$@) {
	return 1;
    }

    # systemd version 232 (e.g. debian stretch) supports the unified hierarchy
    my $sdver = $self->get_systemd_version($init);
    if (!defined($sdver) || $sdver < 232) {
	return 0;
    }

    return 1;
}

sub get_ct_init_path {
    my ($self) = @_;

    my $init_path = "/sbin/init";
    if ($self->ct_is_symlink($init_path)) {
	$init_path = $self->ct_readlink_recursive($init_path);
    }
    return $init_path;
}

sub ssh_host_key_types_to_generate {
    my ($self) = @_;

    return {
	rsa => 'ssh_host_rsa_key',
	dsa => 'ssh_host_dsa_key',
	ecdsa => 'ssh_host_ecdsa_key',
	ed25519 => 'ssh_host_ed25519_key',
    };
}

sub pre_start_hook {
    my ($self, $conf) = @_;

    $self->ct_file_set_contents('/fastboot', ''); # skips fsck, among other things

    $self->setup_init($conf);
    $self->setup_network($conf);
    $self->set_hostname($conf);
    $self->set_dns($conf);
    $self->set_timezone($conf);

    # fixme: what else ?
}

sub post_clone_hook {
    my ($self, $conf) = @_;

    $self->clear_machine_id($conf, 1);
}

sub post_create_hook {
    my ($self, $conf, $root_password, $ssh_keys) = @_;

    $self->clear_machine_id($conf);
    $self->template_fixup($conf);

    &$randomize_crontab($self, $conf);

    $self->set_user_password($conf, 'root', $root_password);
    $self->set_user_authorized_ssh_keys($conf, 'root', $ssh_keys) if $ssh_keys;
    $self->setup_init($conf);
    $self->setup_network($conf);
    $self->set_hostname($conf);
    $self->set_dns($conf);
    $self->set_timezone($conf);

    # fixme: what else ?
}

# File access wrappers for container setup code.
# NOTE: those are not direct part of the Plugin API (yet), avoid using them outside the child plugins
# For user-namespace support these might need to take uid and gid maps into account.

sub ct_is_file_ignored {
    my ($self, $file) = @_;
    my ($name, $path) = fileparse($file);
    return -f "$path/.pve-ignore.$name";
}

sub ct_reset_ownership {
    my ($self, @files) = @_;
    my $conf = $self->{conf};
    return if !$self->{id_map};

    @files = grep { !$self->ct_is_file_ignored($_) } @files;
    return if !@files;

    my $uid = $self->{rootuid};
    my $gid = $self->{rootgid};
    chown($uid, $gid, @files);
}

sub ct_mkdir {
    my ($self, $file, $mask) = @_;
    # mkdir goes by parameter count - an `undef' mode acts like a mode of 0000
    if (defined($mask)) {
	return CORE::mkdir($file, $mask) && $self->ct_reset_ownership($file);
    } else {
	return CORE::mkdir($file) && $self->ct_reset_ownership($file);
    }
}

sub ct_unlink {
    my ($self, @files) = @_;
    foreach my $file (@files) {
	next if $self->ct_is_file_ignored($file);
	CORE::unlink($file);
    }
}

sub ct_rename {
    my ($self, $old, $new) = @_;
    return if $self->ct_is_file_ignored($new);
    CORE::rename($old, $new);
}

sub ct_open_file_read {
    my $self = shift;
    my $file = shift;
    return IO::File->new($file, O_RDONLY, @_);
}

sub ct_open_file_write {
    my $self = shift;
    my $file = shift;
    $file = '/dev/null' if $self->ct_is_file_ignored($file);
    my $fh = IO::File->new($file, O_WRONLY | O_CREAT, @_);
    $self->ct_reset_ownership($fh);
    return $fh;
}

sub ct_make_path {
    my $self = shift;

    my $opts = {};
    if (defined($self->{id_map})) {
	$opts->{owner} = $self->{rootuid};
	$opts->{group} = $self->{rootgid};
    }
    File::Path::make_path(@_, $opts);
}

sub ct_symlink {
    my ($self, $old, $new) = @_;
    return if $self->ct_is_file_ignored($new);
    if (CORE::symlink($old, $new)) {
	if (defined($self->{id_map})) {
	    POSIX::lchown($self->{rootuid}, $self->{rootgid}, $new);
	}
	return 1;
    } else {
	return 0;
    }
}

sub ct_readlink {
    my ($self, $name) = @_;
    return CORE::readlink($name);
}

sub ct_readlink_recursive {
    my ($self, $name) = @_;

    my $res = $name;
    for (my $i = 0; $self->ct_is_symlink($res); $i++) {
	# arbitrary limit, but should be enough for all for our management relevant things
	die "maximal link depth of 10 for resolving '$name' reached, abort\n" if $i >= 10;
	$res = $self->ct_readlink($res);
	$res = abs_path($res);
    }
    return $res;
}

sub ct_file_exists {
    my ($self, $file) = @_;
    return -f $file;
}

sub ct_is_directory {
    my ($self, $file) = @_;
    return -d $file;
}

sub ct_is_symlink {
    my ($self, $file) = @_;
    return -l $file;
}

sub ct_is_executable {
    my ($self, $file) = @_;
    return -x $file
}

sub ct_stat {
    my ($self, $file) = @_;
    return File::stat::stat($file);
}

sub ct_file_read_firstline {
    my ($self, $file) = @_;
    return PVE::Tools::file_read_firstline($file);
}

sub ct_file_get_contents {
    my ($self, $file) = @_;
    return PVE::Tools::file_get_contents($file);
}

sub ct_file_set_contents {
    my ($self, $file, $data, $perms) = @_;
    return if $self->ct_is_file_ignored($file);
    PVE::Tools::file_set_contents($file, $data, $perms);
    $self->ct_reset_ownership($file);
}

# Modify a marked portion of a file.
# Optionally if the file becomes empty it will be deleted.
sub ct_modify_file {
    my ($self, $file, $data, %options) = @_;
    return if $self->ct_is_file_ignored($file);

    my $head = "# --- BEGIN PVE ---\n";
    my $tail = "# --- END PVE ---\n";
    my $perms = $options{perms};
    $data .= "\n" if $data && $data !~ /\n$/;

    if (!$self->ct_file_exists($file)) {
	$self->ct_file_set_contents($file, $head.$data.$tail, $perms) if $data;
	return;
    }

    my $old = $self->ct_file_get_contents($file);
    my @lines = split(/\n/, $old);

    my ($beg, $end);
    foreach my $i (0..(@lines-1)) {
	my $line = $lines[$i];
	$beg = $i if !defined($beg) &&
	    $line =~ /^#\s*---\s*BEGIN\s*PVE\s*/;
	$end = $i if !defined($end) && defined($beg) &&
	    $line =~ /^#\s*---\s*END\s*PVE\s*/i;
	last if defined($beg) && defined($end);
    }

    if (defined($beg) && defined($end)) {
	# Found a section
	if ($data) {
	    chomp $tail;
	    splice @lines, $beg, $end-$beg+1, $head.$data.$tail;
	} else {
	    if ($beg == 0 && $end == (@lines-1)) {
		$self->ct_unlink($file) if $options{delete};
		return;
	    }
	    splice @lines, $beg, $end-$beg+1, $head.$data.$tail;
	}
	$self->ct_file_set_contents($file, join("\n", @lines) . "\n");
    } elsif ($data) {
	# No section found
	my $content = join("\n", @lines);
	chomp $content;
	if (!$content && !$data && $options{delete}) {
	    $self->ct_unlink($file);
	    return;
	}
	$content .= "\n";
	$data = $head.$data.$tail;
	if ($options{replace}) {
	    $self->ct_file_set_contents($file, $data, $perms);
	} elsif ($options{prepend}) {
	    $self->ct_file_set_contents($file, $data . $content, $perms);
	} else { # append
	    $self->ct_file_set_contents($file, $content . $data, $perms);
	}
    }
}

sub remove_pve_sections {
    my ($data) = @_;

    my $head = "# --- BEGIN PVE ---";
    my $tail = "# --- END PVE ---";

    # Remove the sections enclosed with the above headers and footers.
    # from a line (^) starting with '\h*$head'
    # to a line (the other ^) starting with '\h*$tail' up to including that
    # line's end (.*?$).
    return $data =~ s/^\h*\Q$head\E.*^\h*\Q$tail\E.*?$//rgms;
}

# templates from images.linuxcontainers.org have a bogus LXC_NAME line in /etc/hosts
sub remove_lxc_name_from_etc_hosts {
    my ($self) = @_;

    return if ! -e '/etc/hosts';

    my $hosts = $self->ct_file_get_contents('/etc/hosts');
    my @lines = grep { !/^127.0.1.1\s+LXC_NAME$/ } split(/\n/, $hosts);

    $hosts = join("\n", @lines). "\n";

    $self->ct_file_set_contents('/etc/hosts', $hosts);
}

1;
