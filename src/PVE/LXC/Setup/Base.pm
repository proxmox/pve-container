package PVE::LXC::Setup::Base;

use strict;
use warnings;

use File::stat;
use Digest::SHA;
use IO::File;
use Encode;
use Fcntl;
use File::Path;
use File::Spec;

use PVE::INotify;
use PVE::Tools;
use PVE::Network;

sub new {
    my ($class, $conf, $rootdir) = @_;

    return bless { conf => $conf, rootdir => $rootdir }, $class;
}

sub lookup_dns_conf {
    my ($self, $conf) = @_;

    my $nameserver = $conf->{nameserver};
    my $searchdomains = $conf->{searchdomain};

    if (!($nameserver && $searchdomains)) {

	if ($conf->{'testmode'}) {
	    
	    $nameserver = "8.8.8.8 8.8.8.9";
	    $searchdomains = "proxmox.com";
	
	} else {

	    my $host_resolv_conf = $self->{host_resolv_conf};

	    $searchdomains = $host_resolv_conf->{search};

	    my @list = ();
	    foreach my $k ("dns1", "dns2", "dns3") {
		if (my $ns = $host_resolv_conf->{$k}) {
		    push @list, $ns;
		}
	    }
	    $nameserver = join(' ', @list);
	}
    }

    return ($searchdomains, $nameserver);
}

sub update_etc_hosts {
    my ($etc_hosts_data, $hostip, $oldname, $newname, $searchdomains) = @_;

    my $done = 0;

    my @lines;

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
    
    foreach my $line (split(/\n/, $etc_hosts_data)) {
	if ($line =~ m/^#/ || $line =~ m/^\s*$/) {
	    push @lines, $line;
	    next;
	}

	my ($ip, @names) = split(/\s+/, $line);
	if (($ip eq '127.0.0.1') || ($ip eq '::1')) {
	    push @lines, $line;
	    next;
	}

	my $found = 0;
	foreach my $name (@names) {
	    if ($name eq $oldname || $name eq $newname) {
		$found = 1;
	    } else {
		# fixme: record extra names?
	    }
	}
	$found = 1 if defined($hostip) && ($ip eq $hostip);
	
	if ($found) {
	    if (!$done) {
		if (defined($hostip)) {
		    push @lines, "$hostip $all_names";
		} else {
		    push @lines, "127.0.1.1 $namepart";
		}
		$done = 1;
	    }
	    next;
	} else {
	    push @lines, $line;
	}
    }

    if (!$done) {
	if (defined($hostip)) {
	    push @lines, "$hostip $all_names";
	} else {
	    push @lines, "127.0.1.1 $namepart";
	}	
    }

    my $found_localhost = 0;
    foreach my $line (@lines) {
	if ($line =~ m/^127.0.0.1\s/) {
	    $found_localhost = 1;
	    last;
	}
    }

    if (!$found_localhost) {
	unshift @lines, "127.0.0.1 localhost.localnet localhost";
    }
    
    $etc_hosts_data = join("\n", @lines) . "\n";
    
    return $etc_hosts_data;
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

    $self->ct_file_set_contents("/etc/resolv.conf", $data);
}

sub set_hostname {
    my ($self, $conf) = @_;
    
    my $hostname = $conf->{hostname} || 'localhost';

    my $namepart = ($hostname =~ s/\..*$//r);

    my $hostname_fn = "/etc/hostname";
    
    my $oldname = $self->ct_file_read_firstline($hostname_fn) || 'localhost';

    my $hosts_fn = "/etc/hosts";
    my $etc_hosts_data = '';
    
    if ($self->ct_file_exists($hosts_fn)) {
	$etc_hosts_data =  $self->ct_file_get_contents($hosts_fn);
    }

    my ($ipv4, $ipv6) = PVE::LXC::get_primary_ips($conf);
    my $hostip = $ipv4 || $ipv6;

    my ($searchdomains) = $self->lookup_dns_conf($conf);

    $etc_hosts_data = update_etc_hosts($etc_hosts_data, $hostip, $oldname, 
				       $hostname, $searchdomains);
    
    $self->ct_file_set_contents($hostname_fn, "$namepart\n");
    $self->ct_file_set_contents($hosts_fn, $etc_hosts_data);
}

sub setup_network {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

sub setup_init {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

sub setup_systemd_console {
    my ($self, $conf) = @_;

    my $systemd_dir_rel = -x "/lib/systemd/systemd" ?
	"/lib/systemd/system" : "/usr/lib/systemd/system";

    my $systemd_getty_service_rel = "$systemd_dir_rel/getty\@.service";

    return if !$self->ct_file_exists($systemd_getty_service_rel);

    my $raw = $self->ct_file_get_contents($systemd_getty_service_rel);

    my $systemd_container_getty_service_rel = "$systemd_dir_rel/container-getty\@.service";

    # systemd on CenoOS 7.1 is too old (version 205), so there is no
    # container-getty service
    if (!$self->ct_file_exists($systemd_container_getty_service_rel)) {
	if ($raw =~ s!^ConditionPathExists=/dev/tty0$!ConditionPathExists=/dev/tty!m) {
	    $self->ct_file_set_contents($systemd_getty_service_rel, $raw);
	}
    } else {
	# undo above change (in case someone updated systemd)
	if ($raw =~ s!^ConditionPathExists=/dev/tty$!ConditionPathExists=/dev/tty0!m) {
	    $self->ct_file_set_contents($systemd_getty_service_rel, $raw);
	}
    }

    my $ttycount = PVE::LXC::Config->get_tty_count($conf);

    for (my $i = 1; $i < 7; $i++) {
	my $tty_service_lnk = "/etc/systemd/system/getty.target.wants/getty\@tty$i.service";
	if ($i > $ttycount) {
	    $self->ct_unlink($tty_service_lnk);
	} else {
	    if (!$self->ct_is_symlink($tty_service_lnk)) {
		$self->ct_unlink($tty_service_lnk);
		$self->ct_symlink($systemd_getty_service_rel, $tty_service_lnk);
	    }
	}
    }
}

sub setup_container_getty_service {
    my ($self) = @_;
    my $servicefile = '/usr/lib/systemd/system/container-getty@.service';
    my $raw = $self->ct_file_get_contents($servicefile);
    if ($raw =~ s@pts/%I@lxc/tty%I@g) {
	$self->ct_file_set_contents($servicefile, $raw);
    }
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
	my @DHCPMODES = ('none', 'v4', 'v6', 'both');
	my ($NONE, $DHCP4, $DHCP6, $BOTH) = (0, 1, 2, 3);
	my $dhcp = $NONE;

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
	    } elsif ($ip ne 'manual') {
		$has_ipv6 = 1;
		$data .= "Address = $ip\n";
	    }
	}
	if (defined(my $gw = $d->{gw6})) {
	    $data .= "Gateway = $gw\n";
	    if ($has_ipv6 && !PVE::Network::is_ip_in_cidr($gw, $d->{ip6}, 6)) {
		$routes .= "\n[Route]\nDestination = $gw/128\nScope = link\n";
	    }
	}

	$data .= "DHCP = $DHCPMODES[$dhcp]\n";
	$data .= $routes if $routes;

	$self->ct_file_set_contents($filename, $data);
    }
}

sub setup_securetty {
    my ($self, $conf, @add) = @_;

    my $filename = "/etc/securetty";
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

	if ($epw =~ m/^\$TEST\$/) { # for regression tests
	    $last_change = 12345;
	}
	
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
	if ($opt_password !~ m/^\$/) {
	    my $time = substr (Digest::SHA::sha1_base64 (time), 0, 8);
	    $opt_password = crypt(encode("utf8", $opt_password), "\$1\$$time\$");
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

sub pre_start_hook {
    my ($self, $conf) = @_;

    $self->setup_init($conf);
    $self->setup_network($conf);
    $self->set_hostname($conf);
    $self->set_dns($conf);

    # fixme: what else ?
}

sub post_create_hook {
    my ($self, $conf, $root_password) = @_;

    $self->template_fixup($conf);
    
    &$randomize_crontab($self, $conf);
    
    $self->set_user_password($conf, 'root', $root_password);
    $self->setup_init($conf);
    $self->setup_network($conf);
    $self->set_hostname($conf);
    $self->set_dns($conf);
    
    # fixme: what else ?
}

# File access wrappers for container setup code.
# For user-namespace support these might need to take uid and gid maps into account.

sub ct_reset_ownership {
    my ($self, @files) = @_;
    my $conf = $self->{conf};
    return if !$self->{id_map};
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
	CORE::unlink($file);
    }
}

sub ct_rename {
    my ($self, $old, $new) = @_;
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
    my $fh = IO::File->new($file, O_WRONLY | O_CREAT, @_);
    $self->ct_reset_ownership($fh);
    return $fh;
}

sub ct_make_path {
    my $self = shift;
    if ($self->{id_map}) {
	my $opts = pop;
	if (ref($opts) eq 'HASH') {
	    $opts->{owner} = $self->{rootuid} if !defined($self->{owner});
	    $opts->{group} = $self->{rootgid} if !defined($self->{group});
	}
	File::Path::make_path(@_, $opts);
    } else {
	File::Path::make_path(@_);
    }
}

sub ct_symlink {
    my ($self, $old, $new) = @_;
    return CORE::symlink($old, $new);
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
    PVE::Tools::file_set_contents($file, $data, $perms);
    $self->ct_reset_ownership($file);
}

# Modify a marked portion of a file and move it to the beginning of the file.
# If the file becomes empty it will be deleted.
sub ct_modify_file_head_portion {
    my ($self, $file, $head, $tail, $data) = @_;
    if ($self->ct_file_exists($file)) {
	my $old = $self->ct_file_get_contents($file);
	# remove the portion between $head and $tail (all instances via /g)
	$old =~ s/(?:^|(?<=\n))\Q$head\E.*\Q$tail\E//gs;
	chomp $old;
	if ($old) {
	    # old data existed, append and add the trailing newline
	    if ($data) {
		$self->ct_file_set_contents($file, $head.$data.$tail . $old."\n");
	    } else {
		$self->ct_file_set_contents($file, $old."\n");
	    }
	} elsif ($data) {
	    # only our own data will be added
	    $self->ct_file_set_contents($file, $head.$data.$tail);
	} else {
	    # empty => delete
	    $self->ct_unlink($file);
	}
    } else {
	$self->ct_file_set_contents($file, $head.$data.$tail);
    }
}

1;
