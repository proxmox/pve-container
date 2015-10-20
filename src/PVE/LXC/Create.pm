package PVE::LXC::Create;

use strict;
use warnings;
use File::Basename;
use File::Path;
use Data::Dumper;

use PVE::Storage;
use PVE::LXC;
use PVE::LXC::Setup;
use PVE::VZDump::ConvertOVZ;

sub next_free_nbd_dev {
    
    for(my $i = 0;;$i++) {
	my $dev = "/dev/nbd$i";
	last if ! -b $dev;
	next if -f "/sys/block/nbd$i/pid"; # busy
	return $dev;
    }
    die "unable to find free nbd device\n";
}

sub restore_archive {
    my ($archive, $rootdir, $conf) = @_;

    my $userns_cmd = [];

#    we always use the same mapping: 'b:0:100000:65536'
#    if ($conf->{'lxc.id_map'}) {
#	$userns_cmd = ['lxc-usernsexec', '-m', 'b:0:100000:65536', '--'];
#	PVE::Tools::run_command(['chown', '-R', '100000:100000', $rootdir]);
#    }

    my $cmd = [@$userns_cmd, 'tar', 'xpf', $archive, '--numeric-owner', '--totals',
	    '--sparse', '-C', $rootdir];

    # skip-old-files doesn't have anything to do with time (old/new), but is
    # simply -k (annoyingly also called --keep-old-files) without the 'treat
    # existing files as errors' part... iow. it's bsdtar's interpretation of -k
    # *sigh*, gnu...
    push @$cmd, '--skip-old-files';
    push @$cmd, '--anchored';
    push @$cmd, '--exclude' , './dev/*';

    if ($archive eq '-') {
	print "extracting archive from STDIN\n";
	PVE::Tools::run_command($cmd, input => "<&STDIN");
    } else {
	print "extracting archive '$archive'\n";
	PVE::Tools::run_command($cmd);
    }
    
    # determine file type of /usr/bin/file itself to get guests' architecture
    $cmd = [@$userns_cmd, '/usr/bin/file', '-b', '-L', "$rootdir/usr/bin/file"];
    PVE::Tools::run_command($cmd, outfunc => sub {
	shift =~ /^ELF (\d{2}-bit)/; # safely assumes x86 linux
	my $arch_str = $1;
	$conf->{'arch'} = 'amd64'; # defaults to 64bit
	if(defined($arch_str)) {
	    $conf->{'arch'} = 'i386' if $arch_str =~ /32/;
	    print "Detected container architecture: $conf->{'arch'}\n";
	} else {
	    print "CT architecture detection failed, falling back to amd64.\n" .
	          "Edit the config in /etc/pve/nodes/{node}/lxc/{vmid}/config " .
	          "to set another architecture.\n";
	}
    });
}

sub tar_archive_search_conf {
    my ($archive) = @_;

    die "ERROR: file '$archive' does not exist\n" if ! -f $archive;

    my $pid = open(my $fh, '-|', 'tar', 'tf', $archive) ||
       die "unable to open file '$archive'\n";

    my $file;
    while (defined($file = <$fh>)) {
	if ($file =~ m!^(\./etc/vzdump/(pct|vps)\.conf)$!) {
	    $file = $1; # untaint
	    last;
	}
    }

    kill 15, $pid;
    waitpid $pid, 0;
    close $fh;

    die "ERROR: archive contains no configuration file\n" if !$file;
    chomp $file;

    return $file;
}

sub recover_config {
    my ($archive) = @_;

    my $conf_file = tar_archive_search_conf($archive);
    
    my $raw = '';
    my $out = sub {
	my $output = shift;
	$raw .= "$output\n";
    };

    PVE::Tools::run_command(['tar', '-xpOf', $archive, $conf_file, '--occurrence'], outfunc => $out);

    my $conf;
    my $disksize;

    if ($conf_file =~ m/pct\.conf/) {

	$conf = PVE::LXC::parse_pct_config("/lxc/0.conf" , $raw);

	delete $conf->{snapshots};
	delete $conf->{template}; # restored CT is never a template
	
	if (defined($conf->{rootfs})) {
	    my $rootinfo = PVE::LXC::parse_ct_mountpoint($conf->{rootfs});
	    $disksize = $rootinfo->{size} if defined($rootinfo->{size});
	}
	
    } elsif ($conf_file =~ m/vps\.conf/) {
	
	($conf, $disksize) = PVE::VZDump::ConvertOVZ::convert_ovz($raw);
	
    } else {

       die "internal error";
    }

    return wantarray ? ($conf, $disksize) : $conf;
}

sub restore_and_configure {
    my ($vmid, $archive, $rootdir, $conf, $password, $restore) = @_;

    restore_archive($archive, $rootdir, $conf);

    if (!$restore) {
	my $lxc_setup = PVE::LXC::Setup->new($conf, $rootdir); # detect OS

	PVE::LXC::write_config($vmid, $conf); # safe config (after OS detection)
	$lxc_setup->post_create_hook($password);
    } else {
	# restore: try to extract configuration from archive

	my $pct_cfg_fn = "$rootdir/etc/vzdump/pct.conf";
	my $ovz_cfg_fn = "$rootdir/etc/vzdump/vps.conf";
	if (-f $pct_cfg_fn) {
	    my $raw = PVE::Tools::file_get_contents($pct_cfg_fn);
	    my $oldconf = PVE::LXC::parse_pct_config("/lxc/$vmid.conf", $raw);

	    foreach my $key (keys %$oldconf) {
		next if $key eq 'digest' || $key eq 'rootfs' || $key eq 'snapshots';
		$conf->{$key} = $oldconf->{$key} if !defined($conf->{$key});
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

	} else {
	    print "###########################################################\n";
	    print "Backup archive does not contain any configuration\n";
	    print "###########################################################\n";
	}
    }
}

sub create_rootfs {
    my ($storage_cfg, $vmid, $conf, $archive, $password, $restore) = @_;

    my $config_fn = PVE::LXC::config_file($vmid);
    if (-f $config_fn) {
	die "container exists" if !$restore; # just to be sure

	my $old_conf = PVE::LXC::load_config($vmid);
	
	# destroy old container volume
	PVE::LXC::destroy_lxc_container($storage_cfg, $vmid, $old_conf);

	# do not copy all settings to restored container
	foreach my $opt (qw(rootfs digest snapshots arch ostype)) {
	    delete $old_conf->{$opt};
	}
	foreach my $opt (keys %$old_conf) {
	    delete $old_conf->{$opt} if $opt =~ m/^mp\d+$/;
	}

	PVE::LXC::update_pct_config($vmid, $conf, 0, $old_conf);

	PVE::LXC::create_config($vmid, $conf);

    } else {
	
	PVE::LXC::create_config($vmid, $conf);
    }

    eval {
	my $rootdir = PVE::LXC::mount_all($vmid, $storage_cfg, $conf);
        restore_and_configure($vmid, $archive, $rootdir, $conf, $password, $restore);
    };
    if (my $err = $@) {
	warn $err;
	PVE::LXC::umount_all($vmid, $storage_cfg, $conf, 1);
    } else {
	PVE::LXC::umount_all($vmid, $storage_cfg, $conf, 0);
    }

    PVE::Storage::deactivate_volumes($storage_cfg, PVE::LXC::get_vm_volumes($conf));
}

1;
