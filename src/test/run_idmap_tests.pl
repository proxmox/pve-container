#!/usr/bin/perl

use strict;
use warnings;

use TAP::Harness;

my $harness = TAP::Harness->new( { "verbosity" => -2 });
my $res = $harness->runtests( "idmap-test.pm");
exit -1 if $res->{failed};
