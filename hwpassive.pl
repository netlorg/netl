#!/usr/bin/perl
# @(#)netlcc.pl (c) 1999 Graham THE Ollis
#===============================================================================
# front end for the netl c compiler.  this program will generate c code given
# a netl .conf file, then it will involk gcc to compile it.
#
#   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
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

$netl = 'netl';

exec $netl, @ARGV, 'null &hwpassive';
