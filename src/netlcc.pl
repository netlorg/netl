#!/usr/local/bin/perl
# @(#)netlcc.pl (c) 1999 Graham THE Ollis
#===============================================================================
# front end for the netl c compiler.  this program will generate c code given
# a netl .conf file, then it will involk gcc to compile it.
#
#   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#===============================================================================

$netl = '/usr/local/lib/netl-1.10/sbin/netl';
@netl_opts = ('-v-', '--generate-c');

$gcc = 'gcc';
@gcc_opts = ('-I/usr/local/lib/netl-1.10/include');

$install_dir = '/usr/local/lib/netl-1.10/filt';
	# note that we only install compiled .conf files.

$tmp_dir = '/tmp/.netl';
mkdir($tmp_dir, 0777);

@rest = (); @list = (); @mods = ();
for(@ARGV) {
	if(/\.conf$/) {

		($base = $in = $_) =~ s/\.conf$//;
		run($netl, @netl_opts, 
				'--file', $_, 
				'--output-name', "$tmp_dir/$base.c");
		push @list, $base;

	} elsif(/\.c$/) {
		push @mods, $_;
	} else {
		$target = 1 if /^-(c|S|E)$/;
		$no_gcc = 1 if /^-generate-c$/;
		$do_install = 1 if /^-install$/;
		if(/^--version$/) {
			print "netlcc version 1.10(pl)\n";
			run($gcc, '--version');
			exit;
		}
		push @rest, $_;
	}
}

if($no_gcc) {
	for(@list) {
		run('cp', "$tmp_dir/$_.c", '.');
		unlink "$tmp_dir/$_.c";
	}
	exit;
}


for(@mods) {
	($base = $_) =~ s/\.c//;
	@fred = ();
	@fred = ('-shared', '-o', "$base.so") unless $target;
	run($gcc, @gcc_opts, @rest, @fred, $_);
}

for(@list) {
	$base = $_;
	@fred = ();
	@fred = ('-shared', '-o', "$base.so") unless $target;
	run($gcc, @gcc_opts, 
		@rest, @fred,
		"$tmp_dir/$base.c");
	unlink "$tmp_dir/$base.c";
}

if($do_install) {
	for(@list) {
		if(-e "$base.so") {
			run('cp', "$base.so", $install_dir);
		}
	}
}

sub run {
	#print "run: @_\n";
	system(@_);
}
	
