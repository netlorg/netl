/*==============================================================================
| xd
|   code by Graham THE Ollis <ollisg@wwa.com>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
|
|   This program is free software; you can redistribute it and/or modify
|   it under the terms of the GNU General Public License as published by
|   the Free Software Foundation; either version 2 of the License, or
|   (at your option) any later version.
|
|   This program is distributed in the hope that it will be useful,
|   but WITHOUT ANY WARRANTY; without even the implied warranty of
|   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|   GNU General Public License for more details.
|
|   You should have received a copy of the GNU General Public License
|   along with this program; if not, write to the Free Software
|   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
|
|  xd hex dump of a file in a nice formated form, based on neta's hex dump
|  this is primarily a diagnostic tool for testing neta, but you may find
|  it useful, who knows.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  28 Feb 97  G. Ollis	.92 created program
|=============================================================================*/

char *id = "@(#)xd (c) 1997 graham the ollis <ollisg@wwa.com>";

#include <stdio.h>
#include <stdlib.h>

#include "netl/dump.h"

/*==============================================================================
| main
|=============================================================================*/

int
main(int argc, char *argv[])
{
	int i;
	unsigned char *buff;
	size_t size;

	for(i=1; i<argc; i++) {
		if((buff=readentire(argv[i], &size, 0, argv[0]))!=NULL) {
			printf("%s:\n", argv[i]);
			dumpdata(buff, size);
			free(buff);
		}
	}

	return 0;
}

