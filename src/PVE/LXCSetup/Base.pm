package PVE::LXCSetup::Base;

use strict;
use warnings;

use File::stat;
use Digest::SHA;
use IO::File;
use Encode;

use PVE::INotify;
use PVE::Tools;

sub new {
    my ($class, $conf) = @_;

    return bless { conf => $conf }, $class;
}

my $lookup_dns_conf = sub {
    my ($conf) = @_;

    my $nameserver = $conf->{'pve.nameserver'};
    my $searchdomains = $conf->{'pve.searchdomain'};

    if (!($nameserver && $searchdomains)) {

	if ($conf->{'pve.test_mode'}) {
	    
	    $nameserver = "8.8.8.8 8.8.8.9";
	    $searchdomains = "promxox.com";
	
	} else {

	    my $host_resolv_conf = PVE::INotify::read_file('resolvconf');

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
};

my $update_etc_hosts = sub {
    my ($etc_hosts_data, $hostip, $oldname, $newname, $searchdomains) = @_;

    my $done = 0;

    my @lines;

    my $extra_names = '';
    foreach my $domain (PVE::Tools::split_list($searchdomains)) {
	$extra_names .= ' ' if $extra_names;
	$extra_names .= "$newname.$domain";
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
		    push @lines, "$hostip $extra_names $newname";
		} else {
		    push @lines, "127.0.1.1 $newname";
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
	    push @lines, "$hostip $extra_names $newname";
	} else {
	    push @lines, "127.0.1.1 $newname";
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
};

sub set_dns {
    my ($self, $conf) = @_;

    my ($searchdomains, $nameserver) = &$lookup_dns_conf($conf);
    
    my $rootfs = $conf->{'lxc.rootfs'};
    
    my $filename = "$rootfs/etc/resolv.conf";

    my $data = '';

    $data .= "search " . join(' ', PVE::Tools::split_list($searchdomains)) . "\n"
	if $searchdomains;

    foreach my $ns ( PVE::Tools::split_list($nameserver)) {
	$data .= "nameserver $ns\n";
    }

    PVE::Tools::file_set_contents($filename, $data);
}

sub set_hostname {
    my ($self, $conf) = @_;
    
    my $hostname = $conf->{'lxc.utsname'} || 'localhost';

    $hostname =~ s/\..*$//;

    my $rootfs = $conf->{'lxc.rootfs'};

    my $hostname_fn = "$rootfs/etc/hostname";
    
    my $oldname = PVE::Tools::file_read_firstline($hostname_fn) || 'localhost';

    my $hosts_fn = "$rootfs/etc/hosts";
    my $etc_hosts_data = '';
    
    if (-f $hosts_fn) {
	$etc_hosts_data =  PVE::Tools::file_get_contents($hosts_fn);
    }

    my ($ipv4, $ipv6) = PVE::LXC::get_primary_ips($conf);
    my $hostip = $ipv4 || $ipv6;

    my ($searchdomains) = &$lookup_dns_conf($conf);

    $etc_hosts_data = &$update_etc_hosts($etc_hosts_data, $hostip, $oldname, 
					 $hostname, $searchdomains);
    
    PVE::Tools::file_set_contents($hostname_fn, "$hostname\n");
    PVE::Tools::file_set_contents($hosts_fn, $etc_hosts_data);
}

sub setup_network {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

sub setup_init {
    my ($self, $conf) = @_;

    die "please implement this inside subclass"
}

my $replacepw  = sub {
    my ($file, $user, $epw) = @_;

    my $tmpfile = "$file.$$";

    eval  {
	my $src = IO::File->new("<$file") ||
	    die "unable to open file '$file' - $!";

	my $st = File::stat::stat($src) ||
	    die "unable to stat file - $!";

	my $dst = IO::File->new(">$tmpfile") ||
	    die "unable to open file '$tmpfile' - $!";

	# copy owner and permissions
	chmod $st->mode, $dst;
	chown $st->uid, $st->gid, $dst;
	
	while (defined (my $line = <$src>)) {
	    $line =~ s/^${user}:[^:]*:/${user}:${epw}:/;
	    print $dst $line;
	}

	$src->close() || die "close '$file' failed - $!\n";
	$dst->close() || die "close '$tmpfile' failed - $!\n";
    };
    if (my $err = $@) {
	unlink $tmpfile;
    } else {
	rename $tmpfile, $file;
	unlink $tmpfile; # in case rename fails
    }	
};

sub set_user_password {
    my ($self, $conf, $user, $opt_password) = @_;

    my $rootfs = $conf->{'lxc.rootfs'};

    my $pwfile = "$rootfs/etc/passwd";

    return if ! -f $pwfile;

    my $shadow = "$rootfs/etc/shadow";
    
    if (defined($opt_password)) {
	if ($opt_password !~ m/^\$/) {
	    my $time = substr (Digest::SHA::sha1_base64 (time), 0, 8);
	    $opt_password = crypt(encode("utf8", $opt_password), "\$1\$$time\$");
	};
    } else {
	$opt_password = '*';
    }
    
    if (-f $shadow) {
	&$replacepw ($shadow, $user, $opt_password);
	&$replacepw ($pwfile, $user, 'x');
    } else {
	&$replacepw ($pwfile, $user, $opt_password);
    }
}

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

    $self->set_user_password($conf, 'root', $root_password);
    $self->setup_init($conf);
    $self->setup_network($conf);
    $self->set_hostname($conf);
    $self->set_dns($conf);
    
    # fixme: what else ?
}

1;
