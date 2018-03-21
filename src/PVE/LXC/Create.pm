package PVE::LXC::Create;

use strict;
use warnings;
use File::Basename;
use File::Path;
use Data::Dumper;
use Fcntl;

use PVE::Storage;
use PVE::LXC;
use PVE::LXC::Setup;
use PVE::VZDump::ConvertOVZ;
use PVE::Tools;
use POSIX;

sub detect_architecture {
    my ($rootdir) = @_;

    my $supported_elf_class = {
	1 => 'i386',
	2 => 'amd64',
    };

    my $elf_fn = '/bin/sh'; # '/bin/sh' is POSIX mandatory
    my $detect_arch = sub {
	# chroot avoids a problem where we check the binary of the host system
	# if $elf_fn is an absolut symlink (e.g. $rootdir/bin/sh -> /bin/bash)
	chroot($rootdir) or die "chroot '$rootdir' failed: $!\n";
	chdir('/') or die "failed to change to root directory\n";

	open(my $fh, "<", $elf_fn) or die "open '$elf_fn' failed: $!\n";
	binmode($fh);

	my $length = read($fh, my $data, 5) or die "read failed: $!\n";

	# 4 bytes ELF magic number and 1 byte ELF class
	my ($magic, $class) = unpack("A4C", $data);

	die "'$elf_fn' does not resolve to an ELF!\n"
	    if (!defined($class) || !defined($magic) || $magic ne "\177ELF");

	die "'$elf_fn' has unknown ELF class '$class'!\n"
	    if !defined($supported_elf_class->{$class});

	return $supported_elf_class->{$class};
    };

    my $arch = eval { PVE::Tools::run_fork_with_timeout(5, $detect_arch) };
    if (my $err = $@) {
	$arch = 'amd64';
	print "Architecture detection failed: $err\nFalling back to amd64.\n" .
	      "Use `pct set VMID --arch ARCH` to change.\n";
    } else {
	print "Detected container architecture: $arch\n";
    }

    return $arch;
}

sub restore_archive {
    my ($archive, $rootdir, $conf, $no_unpack_error, $bwlimit) = @_;

    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    my $userns_cmd = PVE::LXC::userns_command($id_map);

    my $archive_fh;
    my $tar_input = '<&STDIN';
    my @compression_opt;
    if ($archive ne '-') {
	# GNU tar refuses to autodetect this... *sigh*
	my %compression_map = (
	    '.gz'  => '-z',
	    '.bz2' => '-j',
	    '.xz'  => '-J',
	    '.lzo'  => '--lzop',
	);
	if ($archive =~ /\.tar(\.[^.]+)?$/) {
	    if (defined($1)) {
		@compression_opt = $compression_map{$1}
		    or die "unrecognized compression format: $1\n";
	    }
	} else {
	    die "file does not look like a template archive: $archive\n";
	}
	sysopen($archive_fh, $archive, O_RDONLY)
	    or die "failed to open '$archive': $!\n";
	my $flags = $archive_fh->fcntl(Fcntl::F_GETFD(), 0);
	$archive_fh->fcntl(Fcntl::F_SETFD(), $flags & ~(Fcntl::FD_CLOEXEC()));
	$tar_input = '<&'.fileno($archive_fh);
    }

    my $cmd = [@$userns_cmd, 'tar', 'xpf', '-', @compression_opt, '--totals',
               @PVE::Storage::Plugin::COMMON_TAR_FLAGS,
               '-C', $rootdir];

    # skip-old-files doesn't have anything to do with time (old/new), but is
    # simply -k (annoyingly also called --keep-old-files) without the 'treat
    # existing files as errors' part... iow. it's bsdtar's interpretation of -k
    # *sigh*, gnu...
    push @$cmd, '--skip-old-files';
    push @$cmd, '--anchored';
    push @$cmd, '--exclude' , './dev/*';

    if (defined($bwlimit)) {
	$cmd = [ ['cstream', '-t', $bwlimit*1024], $cmd ];
    }

    if ($archive eq '-') {
	print "extracting archive from STDIN\n";
    } else {
	print "extracting archive '$archive'\n";
    }
    eval { PVE::Tools::run_command($cmd, input => $tar_input); };
    my $err = $@;
    close($archive_fh) if defined $archive_fh;
    die $err if $err && !$no_unpack_error;

    # if arch is set, we do not try to autodetect it
    return if defined($conf->{arch});

    $conf->{arch} = detect_architecture($rootdir);
}

sub recover_config {
    my ($archive) = @_;

    my ($raw, $conf_file) = PVE::Storage::extract_vzdump_config_tar($archive, qr!(\./etc/vzdump/(pct|vps)\.conf)$!);
    my $conf;
    my $mp_param = {};

    if ($conf_file =~ m/pct\.conf/) {

	$conf = PVE::LXC::Config::parse_pct_config("/lxc/0.conf" , $raw);

	delete $conf->{snapshots};
	delete $conf->{template}; # restored CT is never a template

	PVE::LXC::Config->foreach_mountpoint($conf, sub {
	    my ($ms, $mountpoint) = @_;
	    $mp_param->{$ms} = $conf->{$ms};
	});

    } elsif ($conf_file =~ m/vps\.conf/) {

	($conf, $mp_param) = PVE::VZDump::ConvertOVZ::convert_ovz($raw);

    } else {

       die "internal error";
    }

    return wantarray ? ($conf, $mp_param) : $conf;
}

sub restore_configuration {
    my ($vmid, $rootdir, $conf, $restricted) = @_;

    # restore: try to extract configuration from archive

    my $pct_cfg_fn = "$rootdir/etc/vzdump/pct.conf";
    my $pct_fwcfg_fn = "$rootdir/etc/vzdump/pct.fw";
    my $ovz_cfg_fn = "$rootdir/etc/vzdump/vps.conf";
    if (-f $pct_cfg_fn) {
	my $raw = PVE::Tools::file_get_contents($pct_cfg_fn);
	my $oldconf = PVE::LXC::Config::parse_pct_config("/lxc/$vmid.conf", $raw);

	foreach my $key (keys %$oldconf) {
	    next if $key eq 'digest' || $key eq 'rootfs' || $key eq 'snapshots' || $key eq 'unprivileged' || $key eq 'parent';
	    next if $key =~ /^mp\d+$/; # don't recover mountpoints
	    next if $key =~ /^unused\d+$/; # don't recover unused disks
	    if ($restricted && $key eq 'lxc') {
		warn "skipping custom lxc options, restore manually as root:\n";
		warn "--------------------------------\n";
		my $lxc_list = $oldconf->{'lxc'};
		foreach my $lxc_opt (@$lxc_list) {
		    warn "$lxc_opt->[0]: $lxc_opt->[1]\n"
		}
		warn "--------------------------------\n";
		next;
	    }
	    $conf->{$key} = $oldconf->{$key} if !defined($conf->{$key});
	}
	unlink($pct_cfg_fn);

	if (-f $pct_fwcfg_fn) {
	    my $pve_firewall_dir = '/etc/pve/firewall';
	    mkdir $pve_firewall_dir; # make sure the directory exists
	    PVE::Tools::file_copy($pct_fwcfg_fn, "${pve_firewall_dir}/$vmid.fw");
	    unlink $pct_fwcfg_fn;
	}

    } elsif (-f $ovz_cfg_fn) {
	print "###########################################################\n";
	print "Converting OpenVZ configuration to LXC.\n";
	print "Please check the configuration and reconfigure the network.\n";
	print "###########################################################\n";

	my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir); # detect OS
	$conf->{ostype} = $lxc_setup->{conf}->{ostype};
	my $raw = PVE::Tools::file_get_contents($ovz_cfg_fn);
	my $oldconf = PVE::VZDump::ConvertOVZ::convert_ovz($raw);
	foreach my $key (keys %$oldconf) {
	    $conf->{$key} = $oldconf->{$key} if !defined($conf->{$key});
	}
	unlink($ovz_cfg_fn);

    } else {
	print "###########################################################\n";
	print "Backup archive does not contain any configuration\n";
	print "###########################################################\n";
    }
}

1;
