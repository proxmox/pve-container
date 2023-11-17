package PVE::LXC::Create;

use strict;
use warnings;
use File::Basename;
use File::Path;
use Fcntl;

use PVE::RPCEnvironment;
use PVE::Storage::PBSPlugin;
use PVE::Storage;
use PVE::DataCenterConfig;
use PVE::LXC;
use PVE::LXC::Setup;
use PVE::VZDump::ConvertOVZ;
use PVE::Tools;
use POSIX;

sub restore_archive {
    my ($storage_cfg, $archive, $rootdir, $conf, $no_unpack_error, $bwlimit) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive, 1);
    if (defined($storeid)) {
	my $scfg = PVE::Storage::storage_check_enabled($storage_cfg, $storeid);
	if ($scfg->{type} eq 'pbs') {
	    return restore_proxmox_backup_archive($storage_cfg, $archive, $rootdir, $conf, $no_unpack_error, $bwlimit);
	}
    }

    $archive = PVE::Storage::abs_filesystem_path($storage_cfg, $archive) if $archive ne '-';
    restore_tar_archive($archive, $rootdir, $conf, $no_unpack_error, $bwlimit);
}

sub restore_proxmox_backup_archive {
    my ($storage_cfg, $archive, $rootdir, $conf, $no_unpack_error, $bwlimit) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive);
    my $scfg = PVE::Storage::storage_config($storage_cfg, $storeid);

    my ($vtype, $name, undef, undef, undef, undef, $format) =
	PVE::Storage::parse_volname($storage_cfg, $archive);

    die "got unexpected vtype '$vtype'\n" if $vtype ne 'backup';

    die "got unexpected backup format '$format'\n" if $format ne 'pbs-ct';

    my ($id_map, $rootuid, $rootgid) = PVE::LXC::parse_id_maps($conf);
    my $userns_cmd = PVE::LXC::userns_command($id_map);

    my $cmd = "restore";
    my $param = [$name, "root.pxar", $rootdir, '--allow-existing-dirs'];

    if ($no_unpack_error) {
        push(@$param, '--ignore-extract-device-errors');
    }

    PVE::Storage::PBSPlugin::run_raw_client_cmd(
	$scfg, $storeid, $cmd, $param, userns_cmd => $userns_cmd);
}

sub restore_tar_archive {
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
	    '.zst'  => '--zstd',
	);
	if ($archive =~ /\.tar(\.[^.]+)?$/) {
	    if (defined($1)) {
		die "unrecognized compression format: $1\n" if !defined($compression_map{$1});
		@compression_opt = $compression_map{$1};
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
}

sub recover_config {
    my ($storage_cfg, $volid, $vmid) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
    if (defined($storeid)) {
	my $scfg = PVE::Storage::storage_check_enabled($storage_cfg, $storeid);
	if ($scfg->{type} eq 'pbs') {
	    return recover_config_from_proxmox_backup($storage_cfg, $volid, $vmid);
	}
    }

    my $archive = PVE::Storage::abs_filesystem_path($storage_cfg, $volid);
    recover_config_from_tar($archive, $vmid);
}

sub recover_config_from_proxmox_backup {
    my ($storage_cfg, $volid, $vmid) = @_;

    $vmid //= 0;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);
    my $scfg = PVE::Storage::storage_config($storage_cfg, $storeid);

    my ($vtype, $name, undef, undef, undef, undef, $format) =
	PVE::Storage::parse_volname($storage_cfg, $volid);

    die "got unexpected vtype '$vtype'\n" if $vtype ne 'backup';

    die "got unexpected backup format '$format'\n" if $format ne 'pbs-ct';

    my $cmd = "restore";
    my $param = [$name, "pct.conf", "-"];

    my $raw = '';
    my $outfunc = sub { my $line = shift; $raw .= "$line\n"; };
    PVE::Storage::PBSPlugin::run_raw_client_cmd(
	$scfg,  $storeid, $cmd, $param, outfunc => $outfunc);

    my $conf = PVE::LXC::Config::parse_pct_config("/lxc/${vmid}.conf" , $raw);

    delete $conf->{snapshots};

    my $mp_param = {};
    PVE::LXC::Config->foreach_volume($conf, sub {
	my ($ms, $mountpoint) = @_;
	$mp_param->{$ms} = $conf->{$ms};
    });

    return wantarray ? ($conf, $mp_param) : $conf;
}

sub recover_config_from_tar {
    my ($archive, $vmid) = @_;

    my ($raw, $conf_file) = PVE::Storage::extract_vzdump_config_tar($archive, qr!(\./etc/vzdump/(pct|vps)\.conf)$!);
    my $conf;
    my $mp_param = {};
    $vmid //= 0;

    if ($conf_file =~ m/pct\.conf/) {

	$conf = PVE::LXC::Config::parse_pct_config("/lxc/${vmid}.conf" , $raw);

	delete $conf->{snapshots};

	PVE::LXC::Config->foreach_volume($conf, sub {
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
    my ($vmid, $storage_cfg, $archive, $rootdir, $conf, $restricted, $unique, $skip_fw) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive, 1);
    if (defined($storeid)) {
	my $scfg = PVE::Storage::storage_config($storage_cfg, $storeid);
	if ($scfg->{type} eq 'pbs') {
	    return restore_configuration_from_proxmox_backup($vmid, $storage_cfg, $archive, $rootdir, $conf, $restricted, $unique, $skip_fw);
	}
    }
    restore_configuration_from_etc_vzdump($vmid, $rootdir, $conf, $restricted, $unique, $skip_fw);
}

sub restore_configuration_from_proxmox_backup {
    my ($vmid, $storage_cfg, $archive, $rootdir, $conf, $restricted, $unique, $skip_fw) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive);
    my $scfg = PVE::Storage::storage_config($storage_cfg, $storeid);

    my ($vtype, $name, undef, undef, undef, undef, $format) =
	PVE::Storage::parse_volname($storage_cfg, $archive);

    my $oldconf = recover_config_from_proxmox_backup($storage_cfg, $archive, $vmid);

    sanitize_and_merge_config($conf, $oldconf, $restricted, $unique);

    my $cmd = "files";

    my $list = PVE::Storage::PBSPlugin::run_client_cmd($scfg, $storeid, "files", [$name]);
    my $has_fw_conf = grep { $_->{filename} eq 'fw.conf.blob' } @$list;

    if ($has_fw_conf) {
	my $pve_firewall_dir = '/etc/pve/firewall';
	my $pct_fwcfg_target = "${pve_firewall_dir}/${vmid}.fw";
	if ($skip_fw) {
	    warn "ignoring firewall config from backup archive's 'fw.conf', lacking API permission to modify firewall.\n";
	    warn "old firewall configuration in '$pct_fwcfg_target' left in place!\n"
		if -e $pct_fwcfg_target;
	} else {
	    mkdir $pve_firewall_dir; # make sure the directory exists
	    unlink $pct_fwcfg_target;

	    my $cmd = "restore";
	    my $param = [$name, "fw.conf", $pct_fwcfg_target];
	    PVE::Storage::PBSPlugin::run_raw_client_cmd($scfg, $storeid, $cmd, $param);
	}
    }
}

sub sanitize_and_merge_config {
    my ($conf, $oldconf, $restricted, $unique) = @_;

    my $rpcenv = PVE::RPCEnvironment::get();
    my $authuser = $rpcenv->get_user();

    foreach my $key (keys %$oldconf) {
	next if $key eq 'digest' || $key eq 'rootfs' || $key eq 'snapshots' || $key eq 'unprivileged' || $key eq 'parent';
	next if $key =~ /^mp\d+$/; # don't recover mountpoints
	next if $key =~ /^unused\d+$/; # don't recover unused disks
	# we know if it was a template in the restore API call and check if the target
	# storage supports creating a template there
	next if $key =~ /^template$/;

	if ($restricted && $key eq 'features' && !$conf->{unprivileged} && $oldconf->{unprivileged}) {
	    warn "changing from unprivileged to privileged, skipping features\n";
	    next;
	}

	if ($key eq 'lxc' && $restricted) {
	    my $lxc_list = $oldconf->{'lxc'};

	    my $msg = "skipping custom lxc options, restore manually as root:\n";
	    $msg .= "--------------------------------\n";
	    foreach my $lxc_opt (@$lxc_list) {
		$msg .= "$lxc_opt->[0]: $lxc_opt->[1]\n"
	    }
	    $msg .= "--------------------------------";

	    $rpcenv->warn($msg);

	    next;
	}

	if ($key =~ /^net\d+$/ && !defined($conf->{$key})) {
	    PVE::LXC::check_bridge_access($rpcenv, $authuser, $oldconf->{$key});
	}

	if ($unique && $key =~ /^net\d+$/) {
	    my $net = PVE::LXC::Config->parse_lxc_network($oldconf->{$key});
	    my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
	    $net->{hwaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
	    $conf->{$key} = PVE::LXC::Config->print_lxc_network($net);
	    next;
	}
	$conf->{$key} = $oldconf->{$key} if !defined($conf->{$key});
    }
}

sub restore_configuration_from_etc_vzdump {
    my ($vmid, $rootdir, $conf, $restricted, $unique, $skip_fw) = @_;

    # restore: try to extract configuration from archive

    my $pct_cfg_fn = "$rootdir/etc/vzdump/pct.conf";
    my $pct_fwcfg_fn = "$rootdir/etc/vzdump/pct.fw";
    my $ovz_cfg_fn = "$rootdir/etc/vzdump/vps.conf";
    if (-f $pct_cfg_fn) {
	my $raw = PVE::Tools::file_get_contents($pct_cfg_fn);
	my $oldconf = PVE::LXC::Config::parse_pct_config("/lxc/$vmid.conf", $raw);

	sanitize_and_merge_config($conf, $oldconf, $restricted, $unique);

	unlink($pct_cfg_fn);

	# note: this file is possibly from the container itself in backups
	# created prior to pve-container 2.0-40 (PVE 5.x) / 3.0-5 (PVE 6.x)
	# only copy non-empty, non-symlink files, and only if the user is
	# allowed to modify the firewall config anyways
	if (-f $pct_fwcfg_fn && ! -l $pct_fwcfg_fn && -s $pct_fwcfg_fn) {
	    my $pve_firewall_dir = '/etc/pve/firewall';
	    my $pct_fwcfg_target = "${pve_firewall_dir}/${vmid}.fw";
	    if ($skip_fw) {
		warn "ignoring firewall config from backup archive's '$pct_fwcfg_fn', lacking API permission to modify firewall.\n";
		warn "old firewall configuration in '$pct_fwcfg_target' left in place!\n"
		    if -e $pct_fwcfg_target;
	    } else {
		mkdir $pve_firewall_dir; # make sure the directory exists
		PVE::Tools::file_copy($pct_fwcfg_fn, $pct_fwcfg_target);
	    }
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
