/*==============================================================================
| filter.c "hey man, nice shot!"
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
|=============================================================================*/

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

#include "netl/global.h"

#include "netl/io.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/config.h"
#include "netl/options.h"

filt_mod *filters = NULL;
int num_filters=0;
int max_filters=0;

#define DEFAULT_NUM_FILT 10

char *filt_path = "filt";

/*==============================================================================
| resize();
|=============================================================================*/

static void
resize(int i)
{
	filt_mod *tmp = allocate(sizeof(filt_mod) * i);
	memcpy(tmp, filters, sizeof(filt_mod) * i);
	free(filters);
	filters = tmp;
	max_filters = i;
}

/*==============================================================================
| add
|=============================================================================*/

static filt_mod *
add(filt_mod *fm)
{
	if(num_filters == max_filters) {
		resize(max_filters * 2);
	}
	memcpy(&filters[num_filters], fm, sizeof(filt_mod));
	return &filters[num_filters++];
}

/*==============================================================================
| filt_mod *lookup_filter(char *)
| + called by config.y and others.
| + dynamically load (if necessary) and return a filter/action module.
|=============================================================================*/

filt_mod *
lookup_filter(char *name, int filter_code)
{
	int i;
	filt_mod fm;
	char buffer[1024];
	extern char *so_path, *filt_path;

	if(!useIPv6) {
		if(!strcmp(name, "icmp")) {
			name = "icmp4";
		} else if(!strcmp(name, "ip")) {
			name = "ip4";
		} else if(!strcmp(name, "tcp")) {
			name = "tcp4";
		} else if(!strcmp(name, "udp")) {
			name = "udp4";
		}
	}

	if(filters == NULL) {
		filters = allocate(sizeof(filt_mod) * DEFAULT_NUM_FILT);
		num_filters = 0;
		max_filters = DEFAULT_NUM_FILT;
	}

	for(i=0; i<num_filters; i++) {
		if(!strcmp(filters[i].name, name))
			return &filters[i];
	}

	/* otherwise, it hasn't been loaded yet.  do so now... */

	snprintf(buffer, 1024, "%s/%s/%s.so", so_path, filt_path, name);
	fm.handle = nmopen(buffer);
	fm.cf = nmsym(fm.handle, "req");	// that's short for requirement, in case your totally confused... ;)
	set_config_list(fm.cf);
	fm.check = nmsym(fm.handle, "check");
	fm.name = allocate(strlen(name)+1);
	fm.filter_code = filter_code;
	strcpy(fm.name, name);

	return add(&fm);
}
