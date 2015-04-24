package PVE::LXCCreate;

use strict;
use warnings;
use File::Basename;
use File::Path;
use Data::Dumper;

use PVE::Storage;
use PVE::LXC;
use PVE::LXCSetup;

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

    print "extracting archive '$archive'\n";
    PVE::Tools::run_command($cmd);

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
    my ($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password) = @_;

    # fixme: size is ignored here!

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

sub create_rootfs {
    my ($storage_conf, $storage, $size, $vmid, $conf, $archive, $password) = @_;

    PVE::LXC::create_config($vmid, $conf);

    my $cleanup = { files => [], volids => [] };

    eval {
	my $scfg = PVE::Storage::storage_config($storage_conf, $storage);
	if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs') {
	    if (1) {
		create_rootfs_dir_loop($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password);
	    } else {
		create_rootfs_dir($cleanup, $storage_conf, $storage, $size, $vmid, $conf, $archive, $password);
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
