/*==============================================================================
| action.c
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

#include "netl/action.h"
#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/config.h"
#include "netl/io.h"

action_mod *acts = NULL;
int num_acts=0;
int max_acts=0;

#define DEFAULT_NUM_ACT 10

/*==============================================================================
| resize();
|=============================================================================*/

static void
resize(int i)
{
	action_mod *tmp = allocate(sizeof(action_mod) * i);
	memcpy(tmp, acts, sizeof(action_mod) * i);
	free(acts);
	acts = tmp;
	max_acts = i;
}

/*==============================================================================
| add
|=============================================================================*/

static action_mod *
add(action_mod *am)
{
	if(num_acts == max_acts) {
		resize(max_acts * 2);
	}
	memcpy(&acts[num_acts], am, sizeof(action_mod));
	return &acts[num_acts++];
}

/*==============================================================================
| action_mod *lookup_act(char *)
|=============================================================================*/

action_mod *
lookup_act(char *name, int action_code)
{
	int i;
	action_mod am;
	char buffer[1024];
	extern char *so_path, *out_path;

	if(name[0] == '@')
		name++;

	if(acts == NULL) {
		acts = allocate(sizeof(action_mod) * DEFAULT_NUM_ACT);
		num_acts = 0;
		max_acts = DEFAULT_NUM_ACT;
	}

	for(i=0; i<num_acts; i++) {
		if(!strcmp(acts[i].name, name))
			return &acts[i];
	}

	/* otherwise, it hasn't been loaded yet.  do so now... */

	snprintf(buffer, 1024, "%s/%s/%s.so", so_path, out_path, name);
	am.handle = nmopen(buffer);
	am.action = nmsym(am.handle, "action");
	am.action_done = nmsym(am.handle, "action_done");
	am.name = allocate(strlen(name)+1);
	am.action_code = action_code;
	strcpy(am.name, name);

	return add(&am);
}

