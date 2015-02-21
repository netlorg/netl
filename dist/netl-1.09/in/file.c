/*==============================================================================
| file.c
|   by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.ogr>
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
|=============================================================================*/

#include <stdio.h>
#include <string.h>

#include "netl/global.h"
#include "netl/io.h"
#include "netl/ether.h"
#include "netl/ip.h"

/*==============================================================================
| prepare the ethernet card.  this usually involves putting the card in to
| promiscuious mode.
|=============================================================================*/

void
prepare(char *dev)
{
}

/*==============================================================================
| grab - grab the next packet that happens to pass by.
| return the size of the packet, returns -1 on error
|=============================================================================*/

int
grab(char *buf)
{
	FILE *fp;
	char buffer[1024];
	long len=0, r;

	buffer[0] = 0;
	while(buffer[0] == 0) {
		if(feof(stdin)) {
			log("input file EOF");
			die(1, "");
		}
		gets(buffer); len = strlen(buffer);
	}
	if(buffer[len] == '\n')
		buffer[len--]=0;
	fp = fopen(buffer, "r");
	if(fp == NULL) {
		die(1, "could not open \"%s\"!", buffer);
	}
	buffer[0] = 0;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	r=fread(buf, 1, len, fp);
	if(len != r) {
		err("warning, read %d/%d bytes", r, len);
	}
	return len;
}
