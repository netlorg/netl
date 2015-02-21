#===============================================================================
#
#   Copyright (C) 1999 Graham THE Ollis <ollisg@wwa.com>
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

package Netl::Dump;

use Netl;
use IO::File;

sub dumpdata {
	my ($data, $length) = @_;
	$length = length($data) unless defined $length;
	_dumpdata($data, $length);
}

sub dumpdatafile {
	my ($data, $fh) = @_;
	my $length = length($data);
	_dumpdatafile($data, $length, $fh);
}

sub readentire {
	my $fn = shift;
	my $fh = IO::File->new;
	unless($fh->open("<$fn")) {
		Netl::UI::toss_error("unable to read $fn $!");
	}
	my $save = $/;
	undef $/;
	my $data = <$fh>;
	$fh->close;
	$/ = $save;
	return $data;
}

1;
