package PVE::LXC;

use strict;
use warnings;

use lib qw(..);

use PVE::Storage;
use PVE::Storage::Plugin;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::Tools;

use Test::MockModule;
use Test::More;

my $nodename;
my $snapshot_possible;
my $vol_snapshot_possible = {};
my $vol_snapshot_delete_possible = {};
my $vol_snapshot_rollback_possible = {};
my $vol_snapshot_rollback_enabled = {};
my $vol_snapshot = {};
my $vol_snapshot_delete = {};
my $vol_snapshot_rollback = {};
my $running;
my $freeze_possible;
my $kill_possible;

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

sub mocked_volume_snapshot_rollback {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_rollback_enabled->{$volid}) {
	if (defined($vol_snapshot_rollback->{$volid})) {
	    $vol_snapshot_rollback->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot_rollback->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot rollback disabled\n";
    }
}

sub mocked_volume_rollback_is_possible {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    return $vol_snapshot_rollback_possible->{$volid}
	if ($vol_snapshot_rollback_possible->{$volid});
    die "volume_rollback_is_possible failed\n";
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
	if ($cmdstring =~ m/.*\/lxc-stop.*--kill.*/) {
	    if ($kill_possible) {
		$running = 0;
		return 1;
	    } else {
		return 0;
	    }
	}
    }
    die "unexpected run_command call: '$cmdstring', aborting\n";
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

sub testcase_rollback {
    my ($vmid, $snapname, $exp_err, $exp_vol_snap_rollback) = @_;
    subtest "Rolling back to snapshot '$snapname' of vm '$vmid'" => sub {
	plan tests => 3;
	$vol_snapshot_rollback = {};
	$running = 1;
	$exp_vol_snap_rollback = {} if !defined($exp_vol_snap_rollback);
	$@ = undef;
	eval {
	    PVE::LXC::snapshot_rollback($vmid, $snapname);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot_rollback, $exp_vol_snap_rollback, "rolled back to correct volume snapshots");
	ok(test_file("snapshot-expected/rollback/lxc/$vmid.conf", "snapshot-working/rollback/lxc/$vmid.conf"), "config file correct");
    };
}

# BEGIN mocked PVE::LXC::Config methods
sub mocked_config_file_lock {
    return "snapshot-working/pve-test.lock";
}

sub mocked_cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "snapshot-working/$node/lxc/$vmid.conf";
}

sub mocked_load_config {
    my ($class, $vmid, $node) = @_;

    my $filename = PVE::LXC::Config->cfs_config_path($vmid, $node);

    my $raw = PVE::Tools::file_get_contents($filename);

    my $conf = PVE::LXC::parse_pct_config($filename, $raw);
    return $conf;
}

sub mocked_write_config {
    my ($class, $vmid, $conf) = @_;

    my $filename = PVE::LXC::Config->cfs_config_path($vmid);

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
# END mocked PVE::LXC methods

sub sync_container_namespace {
    return;
}

# END redefine PVE::LXC methods

PVE::Tools::run_command("rm -rf snapshot-working");
PVE::Tools::run_command("cp -a snapshot-input snapshot-working");

my $lxc_config_module = new Test::MockModule('PVE::LXC::Config');
$lxc_config_module->mock('config_file_lock', sub { return "snapshot-working/pve-test.lock"; });
$lxc_config_module->mock('cfs_config_path', \&mocked_cfs_config_path);
$lxc_config_module->mock('load_config', \&mocked_load_config);
$lxc_config_module->mock('write_config', \&mocked_write_config);

$running = 1;
$freeze_possible = 1;

printf("\n");
printf("Running prepare tests\n");
printf("\n");
$nodename = "prepare";

printf("\n");
printf("Setting has_feature to return true\n");
printf("\n");
$snapshot_possible = 1;

printf("Successful snapshot_prepare with no existing snapshots\n");
testcase_prepare("101", "test", 0, "test comment", '');

printf("Successful snapshot_prepare with one existing snapshot\n");
testcase_prepare("102", "test2", 0, "test comment", "");

printf("Expected error for snapshot_prepare on locked container\n");
testcase_prepare("200", "test", 0, "test comment", "CT is locked (snapshot)\n");

printf("Expected error for snapshot_prepare with duplicate snapshot name\n");
testcase_prepare("201", "test", 0, "test comment", "snapshot name 'test' already used\n");

printf("Expected error for snapshot_prepare with save_vmstate\n");
testcase_prepare("202", "test", 1, "test comment", "implement me - snapshot_save_vmstate\n");

printf("\n");
printf("Setting has_feature to return false\n");
printf("\n");
$snapshot_possible = 0;

printf("Expected error for snapshot_prepare if snapshots not possible\n");
testcase_prepare("300", "test", 0, "test comment", "snapshot feature is not available\n");

printf("\n");
printf("Running commit tests\n");
printf("\n");
$nodename = "commit";

printf("\n");
printf("Setting has_feature to return true\n");
printf("\n");
$snapshot_possible = 1;

printf("Successful snapshot_commit with one prepared snapshot\n");
testcase_commit("101", "test", "");

printf("Successful snapshot_commit with one committed and one prepared snapshot\n");
testcase_commit("102", "test2", "");

printf("Expected error for snapshot_commit with no snapshot lock\n");
testcase_commit("201", "test", "missing snapshot lock\n");

printf("Expected error for snapshot_commit with invalid snapshot name\n");
testcase_commit("202", "test", "snapshot 'test' does not exist\n");

printf("Expected error for snapshot_commit with invalid snapshot state\n");
testcase_commit("203", "test", "wrong snapshot state\n");

$vol_snapshot_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_possible->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_possible->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_delete_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-3"} = 1;

# possible, but fails
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-4"} = 1;

printf("\n");
printf("Setting up Mocking for PVE::Storage\n");
my $storage_module = new Test::MockModule('PVE::Storage');
$storage_module->mock('config', sub { return undef; });
$storage_module->mock('volume_snapshot', \&mocked_volume_snapshot);
$storage_module->mock('volume_snapshot_delete', \&mocked_volume_snapshot_delete);
$storage_module->mock('volume_snapshot_rollback', \&mocked_volume_snapshot_rollback);
$storage_module->mock('volume_rollback_is_possible', \&mocked_volume_rollback_is_possible);
printf("\tconfig(), volume_snapshot(), volume_snapshot_delete(), volume_snapshot_rollback() and volume_rollback_is_possible() mocked\n");

printf("\n");
printf("Setting up Mocking for PVE::Tools\n");
my $tools_module = new Test::MockModule('PVE::Tools');
$tools_module->mock('run_command' => \&mocked_run_command);
printf("\trun_command() mocked\n");

$nodename = "create";
printf("\n");
printf("Running create tests\n");
printf("\n");

printf("Successful snapshot_create with no existing snapshots\n");
testcase_create("101", "test", 0, "test comment", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_create with one existing snapshots\n");
testcase_create("102", "test2", 0, "test comment", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_create with multiple mps\n");
testcase_create("103", "test", 0, "test comment", "", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test", "local:snapshotable-disk-3" => "test" });

printf("Expected error for snapshot_create when volume snapshot is not possible\n");
testcase_create("201", "test", 0, "test comment", "volume snapshot disabled\n\n");

printf("Expected error for snapshot_create with broken lxc-freeze\n");
$freeze_possible = 0;
testcase_create("202", "test", 0, "test comment", "lxc-[un]freeze disabled\n\n");
$freeze_possible = 1;

printf("Expected error for snapshot_create when mp volume snapshot is not possible\n");
testcase_create("203", "test", 0, "test comment", "volume snapshot disabled\n\n", { "local:snapshotable-disk-1" => "test" }, { "local:snapshotable-disk-1" => "test" });

$nodename = "delete";
printf("\n");
printf("Running delete tests\n");
printf("\n");

printf("Successful snapshot_delete of only existing snapshot\n");
testcase_delete("101", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of leaf snapshot\n");
testcase_delete("102", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete of root snapshot\n");
testcase_delete("103", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of intermediate snapshot\n");
testcase_delete("104", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete with broken volume_snapshot_delete and force=1\n");
testcase_delete("105", "test", 1, "");

printf("Successful snapshot_delete with mp broken volume_snapshot_delete and force=1\n");
testcase_delete("106", "test", 1, "", { "local:snapshotable-disk-1" => "test" });

printf("Expected error when snapshot_delete fails with broken volume_snapshot_delete and force=0\n");
testcase_delete("201", "test", 0, "volume snapshot delete disabled\n");

printf("Expected error when snapshot_delete fails with broken mp volume_snapshot_delete and force=0\n");
testcase_delete("203", "test", 0, "volume snapshot delete disabled\n", { "local:snapshotable-disk-1" => "test" });

printf("Expected error for snapshot_delete with locked config\n");
testcase_delete("202", "test", 0, "CT is locked (backup)\n");

$nodename = "rollback";
printf("\n");
printf("Running rollback tests\n");
printf("\n");

$kill_possible = 1;

printf("Successful snapshot_rollback to only existing snapshot\n");
testcase_rollback("101", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_rollback to leaf snapshot\n");
testcase_rollback("102", "test2", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_rollback to root snapshot\n");
testcase_rollback("103", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_rollback to intermediate snapshot\n");
testcase_rollback("104", "test2", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_rollback with multiple mp\n");
testcase_rollback("105", "test", "", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test", "local:snapshotable-disk-3" => "test" });

printf("Expected error for snapshot_rollback with non-existing snapshot\n");
testcase_rollback("201", "test2", "snapshot 'test2' does not exist\n");

printf("Expected error for snapshot_rollback if volume rollback not possible\n");
testcase_rollback("202", "test", "volume_rollback_is_possible failed\n");

printf("Expected error for snapshot_rollback with incomplete snapshot\n");
testcase_rollback("203", "test", "unable to rollback to incomplete snapshot (snapstate = delete)\n");

printf("Expected error for snapshot_rollback with lock\n");
testcase_rollback("204", "test", "CT is locked (backup)\n");

printf("Expected error for snapshot_rollback with saved vmstate\n");
testcase_rollback("205", "test", "implement me - save vmstate\n", { "local:snapshotable-disk-1" => "test" });

$kill_possible = 0;

printf("Expected error for snapshot_rollback with unkillable container\n");
testcase_rollback("206", "test", "unable to rollback vm 206: vm is running\n");

$kill_possible = 1;

printf("Expected error for snapshot_rollback with mp rollback_is_possible failure\n");
testcase_rollback("207", "test", "volume_rollback_is_possible failed\n");

printf("Expected error for snapshot_rollback with mp rollback failure (results in inconsistent state)\n");
testcase_rollback("208", "test", "volume snapshot rollback disabled\n", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test" });

done_testing();
