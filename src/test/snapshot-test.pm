package PVE::LXC;

use strict;
use warnings;

use lib qw(..);

use PVE::Storage;
use PVE::Storage::Plugin;
use PVE::LXC;
use PVE::Tools;

use Test::MockModule;
use Test::More;

my $nodename;
my $snapshot_possible;
my $vol_snapshot_possible = {};
my $vol_snapshot_delete_possible = {};
my $vol_snapshot = {};
my $vol_snapshot_delete = {};
my $running;
my $freeze_possible;

# Mocked methods

sub mocked_volume_snapshot {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_possible->{$volid}) {
	if (defined($vol_snapshot->{$volid})) {
	    $vol_snapshot->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot disabled\n";
    }
}

sub mocked_volume_snapshot_delete {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_delete_possible->{$volid}) {
	if (defined($vol_snapshot_delete->{$volid})) {
	    $vol_snapshot_delete->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot_delete->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot delete disabled\n";
    }
}

sub mocked_run_command {
    my ($cmd, %param) = @_;
    my $cmdstring;
    if (my $ref = ref($cmd)) {
	$cmdstring = PVE::Tools::cmd2string($cmd);
	if ($cmdstring =~ m/.*\/lxc-(un)?freeze.*/) {
	    return 1 if $freeze_possible;
	    die "lxc-[un]freeze disabled\n";
	}
    }
    die "unexpected run_command call, aborting\n";
}

# Testing methods

sub test_file {
    my ($exp_fn, $real_fn) = @_;
    my $ret;
    eval {
	$ret = system("diff -u '$exp_fn' '$real_fn'");
    };
    die if $@;
    return !$ret;
}

sub testcase_prepare {
    my ($vmid, $snapname, $save_vmstate, $comment, $exp_err) = @_;
    subtest "Preparing snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 2;
	$@ = undef;
	eval {
	    PVE::LXC::snapshot_prepare($vmid, $snapname, $save_vmstate, $comment);
	};
	is($@, $exp_err, "\$@ correct");
	ok(test_file("snapshot-expected/prepare/lxc/$vmid.conf", "snapshot-working/prepare/lxc/$vmid.conf"), "config file correct");
    };
}

sub testcase_commit {
    my ($vmid, $snapname, $exp_err) = @_;
    subtest "Committing snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 2;
	$@ = undef;
	eval {
	    PVE::LXC::snapshot_commit($vmid, $snapname);
	};
	is($@, $exp_err, "\$@ correct");
	ok(test_file("snapshot-expected/commit/lxc/$vmid.conf", "snapshot-working/commit/lxc/$vmid.conf"), "config file correct");
    }
}

sub testcase_create {
    my ($vmid, $snapname, $save_vmstate, $comment, $exp_err, $exp_vol_snap, $exp_vol_snap_delete) = @_;
    subtest "Creating snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 4;
	$vol_snapshot = {};
	$vol_snapshot_delete = {};
	$exp_vol_snap = {} if !defined($exp_vol_snap);
	$exp_vol_snap_delete = {} if !defined($exp_vol_snap_delete);
	$@ = undef;
	eval {
	    PVE::LXC::snapshot_create($vmid, $snapname, $save_vmstate, $comment);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot, $exp_vol_snap, "created correct volume snapshots");
	is_deeply($vol_snapshot_delete, $exp_vol_snap_delete, "deleted correct volume snapshots");
	ok(test_file("snapshot-expected/create/lxc/$vmid.conf", "snapshot-working/create/lxc/$vmid.conf"), "config file correct");
    };
}

sub testcase_delete {
    my ($vmid, $snapname, $force, $exp_err, $exp_vol_snap_delete) = @_;
    subtest "Deleting snapshot '$snapname' of vm '$vmid'" => sub {
	plan tests => 3;
	$vol_snapshot_delete = {};
	$exp_vol_snap_delete = {} if !defined($exp_vol_snap_delete);
	$@ = undef;
	eval {
	    PVE::LXC::snapshot_delete($vmid, $snapname, $force);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot_delete, $exp_vol_snap_delete, "deleted correct volume snapshots");
	ok(test_file("snapshot-expected/delete/lxc/$vmid.conf", "snapshot-working/delete/lxc/$vmid.conf"), "config file correct");
    };
}

# BEGIN redefine PVE::LXC methods 
sub config_file_lock {
    return "snapshot-working/pve-test.lock";
}

sub cfs_config_path {
    my ($vmid, $node) = @_;

    $node = $nodename if !$node;
    return "snapshot-working/$node/lxc/$vmid.conf";
}

sub load_config {
    my ($vmid, $node) = @_;

    my $filename = cfs_config_path($vmid, $node);

    my $raw = PVE::Tools::file_get_contents($filename);

    my $conf = PVE::LXC::parse_pct_config($filename, $raw);
    return $conf;
}

sub write_config {
    my ($vmid, $conf) = @_;

    my $filename = cfs_config_path($vmid);

    if ($conf->{snapshots}) {
	foreach my $snapname (keys %{$conf->{snapshots}}) {
	    $conf->{snapshots}->{$snapname}->{snaptime} = "1234567890"
		if $conf->{snapshots}->{$snapname}->{snaptime};
	}
    }

    my $raw = PVE::LXC::write_pct_config($filename, $conf);

    PVE::Tools::file_set_contents($filename, $raw);
}

sub has_feature {
    my ($feature, $conf, $storecfg, $snapname) = @_;
    return $snapshot_possible;
}

sub check_running {
    return $running;
}

sub sync_container_namespace {
    return;
}

# END redefine PVE::LXC methods

PVE::Tools::run_command("rm -rf snapshot-working");
PVE::Tools::run_command("cp -a snapshot-input snapshot-working");

$running = 1;
$freeze_possible = 1;

printf("");
printf("Running prepare tests");
printf("");
$nodename = "prepare";

printf("");
printf("Setting has_feature to return true");
printf("");
$snapshot_possible = 1;

printf("Successful snapshot_prepare with no existing snapshots");
testcase_prepare("101", "test", 0, "test comment", '');

printf("Successful snapshot_prepare with one existing snapshot");
testcase_prepare("102", "test2", 0, "test comment", "");

printf("Expected error for snapshot_prepare on locked container");
testcase_prepare("200", "test", 0, "test comment", "VM is locked (snapshot)\n");

printf("Expected error for snapshot_prepare with duplicate snapshot name");
testcase_prepare("201", "test", 0, "test comment", "snapshot name 'test' already used\n");

printf("Expected error for snapshot_prepare with save_vmstate");
testcase_prepare("202", "test", 1, "test comment", "implement me - snapshot_save_vmstate\n");

printf("");
printf("Setting has_feature to return false");
printf("");
$snapshot_possible = 0;

printf("Expected error for snapshot_prepare if snapshots not possible");
testcase_prepare("300", "test", 0, "test comment", "snapshot feature is not available\n");

printf("");
printf("Running commit tests");
printf("");
$nodename = "commit";

printf("");
printf("Setting has_feature to return true");
printf("");
$snapshot_possible = 1;

printf("Successful snapshot_commit with one prepared snapshot");
testcase_commit("101", "test", "");

printf("Successful snapshot_commit with one committed and one prepared snapshot");
testcase_commit("102", "test2", "");

printf("Expected error for snapshot_commit with no snapshot lock");
testcase_commit("201", "test", "missing snapshot lock\n");

printf("Expected error for snapshot_commit with invalid snapshot name");
testcase_commit("202", "test", "snapshot 'test' does not exist\n");

printf("Expected error for snapshot_commit with invalid snapshot state");
testcase_commit("203", "test", "wrong snapshot state\n");

$vol_snapshot_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_delete_possible->{"local:snapshotable-disk-1"} = 1;
printf("");
printf("Setting up Mocking for PVE::Storage");
my $storage_module = new Test::MockModule('PVE::Storage');
$storage_module->mock('config', sub { return undef; });
$storage_module->mock('volume_snapshot', \&mocked_volume_snapshot);
$storage_module->mock('volume_snapshot_delete', \&mocked_volume_snapshot_delete);
printf("\tconfig(), volume_snapshot() and volume_snapshot_delete() mocked");

printf("");
printf("Setting up Mocking for PVE::Tools");
my $tools_module = new Test::MockModule('PVE::Tools');
$tools_module->mock('run_command' => \&mocked_run_command);
printf("\trun_command() mocked");

$nodename = "create";
printf("");
printf("Running create tests");
printf("");

printf("Successful snapshot_create with no existing snapshots");
testcase_create("101", "test", 0, "test comment", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_create with one existing snapshots");
testcase_create("102", "test2", 0, "test comment", "", { "local:snapshotable-disk-1" => "test2" });

printf("Expected error for snapshot_create when volume snapshot is not possible");
testcase_create("201", "test", 0, "test comment", "volume snapshot disabled\n\n");

printf("Expected error for snapshot_create with broken lxc-freeze");
$freeze_possible = 0;
testcase_create("202", "test", 0, "test comment", "lxc-[un]freeze disabled\n\n", undef, { "local:snapshotable-disk-1" => "test" });
$freeze_possible = 1;

$nodename = "delete";
printf("");
printf("Running delete tests");
printf("");

printf("Successful snapshot_delete of only existing snapshot");
testcase_delete("101", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of leaf snapshot");
testcase_delete("102", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete of root snapshot");
testcase_delete("103", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of intermediate snapshot");
testcase_delete("104", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete with broken volume_snapshot_delete and force=1");
testcase_delete("105", "test", 1, "");

printf("Expected error when snapshot_delete fails with broken volume_snapshot_delete and force=0");
testcase_delete("201", "test", 0, "volume snapshot delete disabled\n");

printf("Expected error for snapshot_delete with locked config");
testcase_delete("202", "test", 0, "VM is locked (backup)\n");


done_testing();
