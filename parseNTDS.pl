#!/usr/bin/perl

# geoff.jones@cyberis.co.uk - Geoff Jones 19/07/2012 - v0.2

# Perl script to parse the output from NTDSXtract

# Copyright (C) 2012  Cyberis Limited

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


use strict;
use warnings;
use Getopt::Long;

my $file;
my @group;
my $disabled;
my $history;
my $neverloggedon;
my $neverlocks;
my $maxbadpasswordcount = 0;
my $hashes;
my $nopassword = "NO PASSWORD*********************";
my $lmonly;

my $result = GetOptions("file=s"   => \$file,    
                        "group=s"   => \@group,     
                        "removedisabled+"   => \$disabled,    
                        "showhistory+"  => \$history,
			"neverloggedon+" => \$neverloggedon,
			"removelocked=i" => \$maxbadpasswordcount,
			"lmonly+" => \$lmonly,
); 

if (! $file) {
	usage();
	exit 1;
}

open (NTDS, $file) or die $_;

print STDERR "[INFO] Reading ntdsXtract output...\n";
my $contents;
while (<NTDS>) {
	$contents .= $_;
}

my @records = split(/^Record ID: /m, $contents);
print STDERR "[INFO] Complete, " . @records . " records read.\n";

foreach (@records) {
	my $instance = $_;
	my $username;
	my @history;
	my $principalname ;
	
	if ($instance =~ /User name:\s+(.*)/) {
		$username = quotemeta($1);
		$instance =~ /SAM Account name:\s+(.*)/;
		$instance =~ /User principal name: +([^\n]+)\n/s;
		$principalname = $1;
	}
	else {
		next;
	}

	if ($disabled) {
		if ($instance =~ /User Account Control(.*?)\n[A-Z]/s) {
			if ($1 =~ /Disabled/i) {
				next;
			}
		}
	}

	if ($maxbadpasswordcount > 0) {
		if ($instance =~ /Bad password count:.*?([\-0-9])+/) {
			if ($1 >= $maxbadpasswordcount) {
				next;
			}
		}
	}

	if (@group) {
		my $match = 0;
		foreach (@group) {
			if ($instance =~ /$_/i) {
				$match = 1;
			}
		}
		next if $match == 0;
	}

	my $nthash;
	my $lmhash = $nopassword;
	$instance =~ /SID:.*-([0-9]+)/;
	my $sid = $1;

	if ($instance =~ /$username:\$NT\$([^\:]+):/) {
		$nthash = $1;
	}

	if ($instance =~ /$username:[^\$]([^\:]+):/) {
		$lmhash = $1;
	}

	if ($history) {
	
		my @hashes = ( $instance =~ /$username[^\:].*:::/g );
	
		my %users;

		foreach (@hashes) {
			my $hash = $_;
			
			$hash =~ /(.*?)_(nt|lm)history([0-9]+)\:/;
			my $hashuser = $1."_history".$3;
			my $baseuser = $1;
			my $number = $3;

			if ($hash =~ /$baseuser\_nthistory$number:\$NT\$([^\:]+):/) {
				$users{$hashuser}{nthash} = $1;
			}

			if ($hash =~ /$baseuser\_lmhistory$number:[^\$]([^\:]+):/) {
				$users{$hashuser}{lmhash} = $1 ;
			}
		}
		foreach (sort(keys %users)) {
			my $historylmhash = $users{$_}{lmhash} || $nopassword;			
			my $historynthash = $users{$_}{nthash};
			next if ($lmonly && $historylmhash eq $nopassword);
			push (@history, "${principalname}_history_" . @history . "\:$sid\:$historylmhash:$historynthash\:::\n");	
		}
	}

  	next if (($lmonly && $lmhash eq $nopassword) || ! $nthash ) ;

	print "$principalname\:$sid\:$lmhash\:$nthash\:::\n";

	if ($history) {
		foreach (@history) {
			print "$_";
		}
	}
}

sub usage {
	print "./parseNTDSoutput.pl -f <FILE> [--lmonly Only display accounts with LM passwords] [-group &nbsp; &lt;GROUP NAME&gt;]... [--removedisabled Remove disabled accounts] [--removedlocked &lt;LOCK COUNT&gt;] [--showhistory Include historic passwords]\n\n";
}
