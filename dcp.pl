#!/usr/bin/perl -w
# @(#)nets.pl (c) 1997 Graham THE Ollis
#===============================================================================
# nets.pl - send a message to netl or related network listening tool.
#           for this version you will need netcat.  hopefully this will be
#           unnecessary in later versions.
#
#   Copyright (C) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>
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
# History:
# Date       Author     Comment
# ----       ------     -------
# 07 mar 97  G. Ollis	created script
#===============================================================================

require 5;

if($#ARGV == -1) {
  print STDERR "usage: $0 message [port]\n";
  exit 2;
}

$message = shift @ARGV;
$port = shift @ARGV;
$port = 47 unless defined $port;

$data = pack 'Nn', $$, length($message);
$pid = open(NC, "|nc -u localhost $port");
print NC $data;
print NC $message;
#sleep 1;		# hopefully this is not necessary
kill $pid;
