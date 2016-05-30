package PVE::VZDump::ConvertOVZ;

use strict;
use warnings;
use POSIX qw (LONG_MAX);

my $res_unlimited = LONG_MAX;

sub ovz_config_extract_mem_swap {
    my ($veconf, $unit) = @_;

    $unit = 1 if !$unit;

    my ($mem, $swap) = (int((512*1024*1024 + $unit - 1)/$unit), 0);

    my $maxpages = ($res_unlimited / 4096);

    if ($veconf->{swappages}) {
	if ($veconf->{physpages} && $veconf->{physpages}->{lim} &&
	    ($veconf->{physpages}->{lim} < $maxpages)) {
	    $mem = int(($veconf->{physpages}->{lim} * 4096 + $unit - 1) / $unit);
	}
	if ($veconf->{swappages}->{lim} && ($veconf->{swappages}->{lim} < $maxpages)) {
	    $swap = int (($veconf->{swappages}->{lim} * 4096 + $unit - 1) / $unit);
	}
    } else {
	if ($veconf->{vmguarpages} && $veconf->{vmguarpages}->{bar} &&
	    ($veconf->{vmguarpages}->{bar} < $maxpages)) {
	    $mem = int(($veconf->{vmguarpages}->{bar} * 4096 + $unit - 1) / $unit);
	}
    }

    return ($mem, $swap);
}

sub parse_res_num_ignore {
    my ($key, $text) = @_;

    if ($text =~ m/^(\d+|unlimited)(:.*)?$/) {
	return { bar => $1 eq 'unlimited' ? $res_unlimited : $1 };
    }

    return undef;
}

sub parse_res_num_num {
    my ($key, $text) = @_;

    if ($text =~ m/^(\d+|unlimited)(:(\d+|unlimited))?$/) {
	my $res = { bar => $1 eq 'unlimited' ? $res_unlimited : $1 };
	if (defined($3)) {
	    $res->{lim} = $3 eq 'unlimited' ? $res_unlimited : $3;
	} else {
	    $res->{lim} = $res->{bar};
	}
	return $res;
    }

    return undef;
}

sub parse_res_bar_limit {
    my ($text, $base) = @_;

    return $res_unlimited if $text eq 'unlimited';

    if ($text =~ m/^(\d+)([TGMKP])?$/i) {
	my $val = $1;
	my $mult = $2 ? lc($2) : '';
	if ($mult eq 'k') {
	    $val = $val * 1024;
	} elsif ($mult eq 'm') {
	    $val = $val * 1024 * 1024;
	} elsif ($mult eq 'g') {
	    $val = $val * 1024 * 1024 * 1024;
	} elsif ($mult eq 't') {
	    $val = $val * 1024 * 1024 * 1024 * 1024;
	} elsif ($mult eq 'p') {
	    $val = $val * 4096;
	} else {
	    return $val;
	}
	return int($val/$base);
    }

    return undef;
}

sub parse_res_bytes_bytes {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);
    $a[1] = $a[0] if !defined($a[1]);

    my $bar = parse_res_bar_limit($a[0], 1);
    my $lim = parse_res_bar_limit($a[1], 1);

    if (defined($bar) && defined($lim)) {
	return { bar => $bar, lim => $lim };
    }

    return undef;
}

sub parse_res_block_block {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);
    $a[1] = $a[0] if !defined($a[1]);

    my $bar = parse_res_bar_limit($a[0], 1024);
    my $lim = parse_res_bar_limit($a[1], 1024);

    if (defined($bar) && defined($lim)) {
	return { bar => $bar, lim => $lim };
    }

    return undef;
}

sub parse_res_pages_pages {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);
    $a[1] = $a[0] if !defined($a[1]);

    my $bar = parse_res_bar_limit($a[0], 4096);
    my $lim = parse_res_bar_limit($a[1], 4096);

    if (defined($bar) && defined($lim)) {
	return { bar => $bar, lim => $lim };
    }

    return undef;
}

sub parse_res_pages_unlimited {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);

    my $bar = parse_res_bar_limit($a[0], 4096);

    if (defined($bar)) {
	return { bar => $bar, lim => $res_unlimited };
    }

    return undef;
}

sub parse_res_pages_ignore {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);

    my $bar = parse_res_bar_limit($a[0], 4096);

    if (defined($bar)) {
	return { bar => $bar };
    }

    return undef;
}

sub parse_res_ignore_pages {
    my ($key, $text) = @_;

    my @a = split(/:/, $text);
    $a[1] = $a[0] if !defined($a[1]);

    my $lim = parse_res_bar_limit($a[1] , 4096);

    if (defined($lim)) {
	return { bar => 0, lim => $lim };
    }

    return undef;
}

sub parse_boolean {
    my ($key, $text) = @_;

    return { value => 1 } if $text =~ m/^(yes|true|on|1)$/i;
    return { value => 0 } if $text =~ m/^(no|false|off|0)$/i;

    return undef;
};

sub parse_integer {
    my ($key, $text) = @_;

    if ($text =~ m/^(\d+)$/) {
	return { value => int($1) };
    }

    return undef;
};

my $ovz_ressources = {
    numproc => \&parse_res_num_ignore,
    numtcpsock => \&parse_res_num_ignore,
    numothersock => \&parse_res_num_ignore,
    numfile => \&parse_res_num_ignore,
    numflock => \&parse_res_num_num,
    numpty => \&parse_res_num_ignore,
    numsiginfo => \&parse_res_num_ignore,
    numiptent => \&parse_res_num_ignore,

    vmguarpages => \&parse_res_pages_unlimited,
    oomguarpages => \&parse_res_pages_unlimited,
    lockedpages => \&parse_res_pages_ignore,
    privvmpages => \&parse_res_pages_pages,
    shmpages => \&parse_res_pages_ignore,
    physpages => \&parse_res_pages_pages,
    swappages => \&parse_res_ignore_pages,

    kmemsize => \&parse_res_bytes_bytes,
    tcpsndbuf => \&parse_res_bytes_bytes,
    tcprcvbuf => \&parse_res_bytes_bytes,
    othersockbuf => \&parse_res_bytes_bytes,
    dgramrcvbuf => \&parse_res_bytes_bytes,
    dcachesize => \&parse_res_bytes_bytes,

    disk_quota => \&parse_boolean,
    diskspace => \&parse_res_block_block,
    diskinodes => \&parse_res_num_num,
    quotatime => \&parse_integer,
    quotaugidlimit => \&parse_integer,

    cpuunits => \&parse_integer,
    cpulimit => \&parse_integer,
    cpus => \&parse_integer,
    cpumask => 'string',
    meminfo => 'string',
    iptables => 'string',

    ip_address => 'string',
    netif => 'string',
    hostname => 'string',
    nameserver => 'string',
    searchdomain => 'string',

    name => 'string',
    description => 'string',
    onboot => \&parse_boolean,
    initlog => \&parse_boolean,
    bootorder => \&parse_integer,
    ostemplate => 'string',
    ve_root => 'string',
    ve_private => 'string',
    disabled => \&parse_boolean,
    origin_sample => 'string',
    noatime => \&parse_boolean,
    capability => 'string',
    devnodes => 'string',
    devices => 'string',
    pci => 'string',
    features => 'string',
    ioprio => \&parse_integer,

};

my $parse_ovz_config = sub {
    my ($raw) = @_;

    my $data = {};

    return undef if !defined($raw);

    while ($raw && $raw =~ /^(.*?)(\n|$)/mg) {
	my $line = $1;

	next if $line =~ m/^\#/;
	next if $line =~ m/^\s*$/;

	if ($line =~ m/^\s*([A-Z][A-Z0-9_]*)\s*=\s*\"(.*)\"\s*$/i) {
	    my $name = lc($1);
	    my $text = $2;
	    my $parser = $ovz_ressources->{$name};
	    if (!$parser || !ref($parser)) {
		$data->{$name}->{value} = $text;
		next;
	    } else {
		if (my $res = &$parser($name, $text)) {
		    $data->{$name} = $res;
		    next;
		}
	    }
	}
	die "unable to parse config line: $line\n";
    }

    return $data;
};

sub convert_ovz {
   my ($raw) = @_;

   my $conf = {};

   my $ovz_conf = &$parse_ovz_config($raw);

   my $disksize = $ovz_conf->{'diskspace'}->{'bar'} * 1024;
   
   my ($mem, $swap) = ovz_config_extract_mem_swap($ovz_conf, 0);

   $conf->{memory} = $mem / 1024 / 1024;

   $conf->{swap} = ($swap + $mem) / 1024 / 1024;

   $conf->{cpuunits} = 1024;

   $conf->{cpulimit} = $ovz_conf->{cpus}->{value} if $ovz_conf->{cpus};

   $conf->{hostname} = $ovz_conf->{hostname}->{value};

   my $mp_param = { rootfs => "local:convertedovz,size=$disksize" };

   return wantarray ? ($conf, $mp_param) : $conf;
}
