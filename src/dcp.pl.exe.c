#include <stdio.h>
#include "netl/version.h"

int
main(int argc, char *argv[])
{
        FILE *fp;

        fp = fopen("dcp.pl", "w");
        if(fp == NULL) {
                fprintf(stderr, "hrm.  i could not open dcp.pl for writing.");
                return 1;
        }

	fprintf(fp, "#!%s
# @(#)dcp.pl (c) 1997 Graham THE Ollis
#===============================================================================
# dcp.pl -  send a message to netl or related network listening tool.
#           for this version you will need netcat.  hopefully this will be
#           unnecessary in later versions.
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
# History:
# Date       Author     Comment
# ----       ------     -------
# 07 mar 97  G. Ollis	created script
#===============================================================================

use Socket;

while(defined $ARGV[0] and $ARGV[0] =~ m/^-/) {
	$option = shift @ARGV;
	if($option eq '-o') {
		$old = 1;
	}
}

if($#ARGV == -1) {
	print STDERR \"usage: $0 [-o] message [port]\\n\";
	exit 2;
}

$message = shift @ARGV;
$port = shift @ARGV || 47;
$len = length $message; 

if(defined $old) {
	$data = pack 'Nn', $$, $len;
	$pid = open(NC, \"|nc -u localhost $port\");
	print NC $data;
	print NC $message;
	kill $pid;
} else {
	$data = pack \"Nna$len\", $$, $len, $message;
	$proto = getprotobyname('udp') ||
		die \"getprotobyname(): $!\\n\";
	socket(Socket_Handle, PF_INET, SOCK_DGRAM, $proto) ||
		die \"socket(): $!\\n\";
	$iaddr = gethostbyname('localhost') ||
		die \"gethostbyname(): $!\\n\";
	$sin = sockaddr_in($port, $iaddr) ||
		die \"sockaddr_in(): $!\\n\";
	send(Socket_Handle, $data, 0, $sin) ||
		die \"send(): $!\\n\";
}
	", NETL_PERLPATH);

	fclose(fp);
	return 0;
}

