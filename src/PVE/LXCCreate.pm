package PVE::LXCCreate;

use strict;
use warnings;
use File::Basename;
use File::Path;
use Data::Dumper;

use PVE::Storage;
use PVE::LXC;
use PVE::LXCSetup;

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

    # we always use the same mapping: 'b:0:100000:65536'
    my $userns_cmd;

    if ($conf->{'lxc.id_map'}) {
	$userns_cmd = ['lxc-usernsexec', '-m', 'b:0:100000:65536', '--'];
    } else {
	$userns_cmd = [];
    }

    my $cmd;

    if ($conf->{'lxc.id_map'}) {
	PVE::Tools::run_command(['chown', '-R', '100000:100000', $rootdir]);
    }

    $cmd = [@$userns_cmd, 'tar', 'xpf', $archive, '--numeric-owner', '--totals',
	    '--sparse', '-C', $rootdir];

    push @$cmd, '--anchored';
    push @$cmd, '--exclude' , './dev/*';

    if ($archive eq '-') {
	print "extracting archive from STDIN\n";
	PVE::Tools::run_command($cmd, input => "<&STDIN");
   } else {
	print "extracting archive '$archive'\n";
	PVE::Tools::run_command($cmd);
    }
    
    # is this really required? what for?
    #$cmd = [@$userns_cmd, 'mkdir', '-p', "$rootdir/dev/pts"];
    #PVE::Tools::run_command($cmd);

    # template/OS specific configuration
    $conf->{'lxc.arch'} = 'i386'; #fixme: || x86_64
}

sub restore_and_configure {
    my ($vmid, $archive, $rootdir, $conf, $password) = @_;

    restore_archive($archive, $rootdir, $conf);

    PVE::LXC::write_config($vmid, $conf);

    my $lxc_setup = PVE::LXCSetup->new($conf, $rootdir); # detect OS

    PVE::LXC::write_config($vmid, $conf); # safe config (after OS detection)

    $lxc_setup->post_create_hook($password);
}

# directly use a storage directory
sub create_rootfs_dir {
    my ($cleanup, $storage_conf, $storage, $vmid, $conf, $archive, $password) = @_;

    # note: there is no size limit
    $conf->{'pve.disksize'} = 0;

    my $private = PVE::Storage::get_private_dir($storage_conf, $storage, $vmid);
    mkdir($private) || die "unable to create container private dir '$private' - $!\n";

    push @{$cleanup->{files}}, $private;
    $conf->{'lxc.rootfs'} = $private;

    restore_and_configure($vmid, $archive, $private, $conf, $password);
}

# create a raw file, then loop mount
sub create_rootfs_dir_loop {
    my ($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password) = @_;

    my $volid = PVE::Storage::vdisk_alloc($storage_conf, $storage, $vmid, 'raw', "vm-$vmid-rootfs.raw", $size);
    $conf->{'pve.disksize'} = $size/(1024*1024);

    push @{$cleanup->{volids}}, $volid;

    my $image_path = PVE::Storage::path($storage_conf, $volid);
    $conf->{'lxc.rootfs'} = "loop:${image_path}";

    my $cmd = ['mkfs.ext4', $image_path];
    PVE::Tools::run_command($cmd);

    print "allocated image: $image_path\n";

    my $mountpoint;

    my $loopdev;
    eval {
	my $parser = sub {
	    my $line = shift;
	    $loopdev = $line if $line =~m|^/dev/loop\d+$|;
	};
	PVE::Tools::run_command(['losetup', '--find', '--show', $image_path], outfunc => $parser);

	my $tmp = "/var/lib/lxc/$vmid/rootfs";
	File::Path::mkpath($tmp);
	PVE::Tools::run_command(['mount', '-t', 'ext4', $loopdev, $tmp]);
	$mountpoint = $tmp;

	$conf->{'pve.volid'} = $volid;
	restore_and_configure($vmid, $archive, $mountpoint, $conf, $password);
    };
    if (my $err = $@) {
	if ($mountpoint) {
	    eval { PVE::Tools::run_command(['umount', '-d', $mountpoint]) };
	    warn $@ if $@;
	} else {
	    eval { PVE::Tools::run_command(['losetup', '-d', $loopdev]) if $loopdev; };
	    warn $@ if $@;
	}
	die $err;
    }

    PVE::Tools::run_command(['umount', '-l', '-d', $mountpoint]);
}

# create a file, then mount with qemu-nbd
sub create_rootfs_dir_qemu {
    my ($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password) = @_;

    my $format = 'qcow2';
    
    my $volid = PVE::Storage::vdisk_alloc($storage_conf, $storage, $vmid, 
					  $format, "vm-$vmid-rootfs.$format", $size);

    $conf->{'pve.disksize'} = $size/(1024*1024);

    push @{$cleanup->{volids}}, $volid;

    my $image_path = PVE::Storage::path($storage_conf, $volid);
    $conf->{'lxc.rootfs'} = "nbd:${image_path}";

    print "allocated image: $image_path\n";

    my $mountpoint;

    my $nbd_dev;
    eval {
	$nbd_dev = next_free_nbd_dev();
	PVE::Tools::run_command(['qemu-nbd', '-c', $nbd_dev, $image_path]);

	my $cmd = ['mkfs.ext4', $nbd_dev];
	PVE::Tools::run_command($cmd);


	my $tmp = "/var/lib/lxc/$vmid/rootfs";
	File::Path::mkpath($tmp);
	PVE::Tools::run_command(['mount', '-t', 'ext4', $nbd_dev, $tmp]);
	$mountpoint = $tmp;

	$conf->{'pve.volid'} = $volid;
	restore_and_configure($vmid, $archive, $mountpoint, $conf, $password);
    };
    if (my $err = $@) {
	if ($mountpoint) {
	    eval { PVE::Tools::run_command(['umount', $mountpoint]); };
	    warn $@ if $@;
	}
	if ($nbd_dev) {
	    eval { PVE::Tools::run_command(['qemu-nbd', '-d', $nbd_dev]); };
	    warn $@ if $@;
	}
	die $err;
    }

    PVE::Tools::run_command(['umount', $mountpoint]);
    PVE::Tools::run_command(['qemu-nbd', '-d', $nbd_dev]);
}

sub create_rootfs {
    my ($storage_conf, $storage, $disk_size_gb, $vmid, $conf, $archive, $password, $restore) = @_;

    my $config_fn = PVE::LXC::config_file($vmid);
    if (-f $config_fn) {
	die "container exists" if !$restore; # just to be sure

	my $old_conf = PVE::LXC::load_config($vmid);

	if (!defined($disk_size_gb) && defined($old_conf->{'pve.disksize'})) {
	    $disk_size_gb = $old_conf->{'pve.disksize'};
	}
	    
	# destroy old container
	PVE::LXC::destory_lxc_container($storage_conf, $vmid, $old_conf);

	# merge old config?
	
	PVE::LXC::create_config($vmid, $conf);

    } else {
	
	PVE::LXC::create_config($vmid, $conf);
    }

    my $size = 4*1024*1024; # defaults to 4G	    

    $size = int($disk_size_gb*1024) * 1024 if defined($disk_size_gb);
    
    my $cleanup = { files => [], volids => [] };

    eval {
	my $scfg = PVE::Storage::storage_config($storage_conf, $storage);
	if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
	    if ($size > 0) {
		create_rootfs_dir_loop($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password);
	    } else {
		create_rootfs_dir($cleanup, $storage_conf, $storage, $vmid, $conf, $archive, $password);
	    }
	} else {
	    die "unable to create containers on storage type '$scfg->{type}'\n";
	}
    };
    if (my $err = $@) {
	# cleanup
	File::Path::rmtree($cleanup->{files});
	foreach my $volid (@{$cleanup->{volids}}) {
	    eval { PVE::Storage::vdisk_free($storage_conf, $volid); };
	    warn $@ if $@;
	}

	PVE::LXC::destroy_config($vmid);

	die $err;
    }
}

1;
