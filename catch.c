/*==============================================================================
| catch
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
|  Date       Name	Revision
|  ---------  --------  --------
|  04 Jul 99  G. Ollis	created module
|=============================================================================*/


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "netl/global.h"

#include "netl/catch.h"
#include "netl/io.h"

typedef struct {
	char id[4];
	size_t str_len;
	size_t packet_len;
} header;

static header h;
static int fd;
static FILE *fp;

void netl_catch_prepare(int fd_val)
{
	int flags;

	fd = fd_val;

	if((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		err("unable to fcntl(fd, F_GETFL, 0)\n");
		exit(1);
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		err("unable to fcntl(fd, F_SETFL, flags | O_NONBLOCK)\n");
		exit(1);
	}

	fp = fdopen(fd, "r");
	if(fp == NULL) {
		err("could not fdopen %d\n", fd);
		exit(1);
	}
}

ret_entry *
netl_catch_catch(void)
{
	static ret_entry re = { NULL, NULL, 0 };
	int i;


	for(i=0; i<10; i++) {
		if(fread(&h, sizeof(header), 1, fp) != 0) {
			if(memcmp(h.id, "NETL", 4)) {
				err("sig doesn't match \"%4s\" should be NETL\n", h.id);
				exit(1);
			}
/*			if(h.str_len > name_len) {
				if(re.name != NULL)
					free(re.name);
				name_len = h.str_len;
				re.name = allocate(name_len);
			}
			if(h.packet_len > re.packet_len) {
				if(re.packet != NULL)
					free(re.packet);
				re.packet_len = h.packet_len;
				re.packet = allocate(re.packet_len);
			}*/
			re.name = allocate(h.str_len);
			re.packet = allocate(re.packet_len = h.packet_len);
			fread(re.name, h.str_len, 1, fp);
			fread(re.packet, re.packet_len, 1, fp);
			return &re;
		}
	}
	return NULL;
}

