/*==============================================================================
| log/dump output module for netl
|   by Graham THE Ollis <ollisg@wwa.com>
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
|  Date       Name	Revision
|  ---------  --------  --------
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include <stdio.h>

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "netl/io.h"

int action_done;

void (*action_log)(u8 *, struct configitem *, size_t);
char **extra_string;
char *(*action_dump)(u8 *, struct configitem *, size_t);
void *handle_log, *handle_dump;

/*==============================================================================
| dump ip datagram to disk
|=============================================================================*/

void
action(u8 *dg, struct configitem *cf, size_t len)
{
	*extra_string = action_dump(dg, cf, len);
	action_log(dg, cf, len);
	*extra_string = "";
	action_done = 1;
}

/*==============================================================================
| constructor
|=============================================================================*/

static int semaphore = 0;

void
construct(void)
{
	char buffer[255];

	semaphore++;
	if(semaphore != 1)
		return;

	snprintf(buffer, 255, "%s/out/log.so", so_path);
	handle_log = nmopen(buffer);

	action_log = nmsym(handle_log, "action");
	extra_string = nmsym(handle_log, "extra_string");

	snprintf(buffer, 255, "%s/out/dump.so", so_path);
	handle_dump = nmopen(buffer);

	action_dump = nmsym(handle_dump, "action");
	if(action_dump == NULL) {
		err("could not resolve necessary sysmbols in %s!", buffer);
		exit(1);
	}

}

/*==============================================================================
| destructor
|=============================================================================*/

void
destroy(void)
{
	semaphore--;
	if(semaphore != 0)
		return;
	nmclose(handle_log);
	nmclose(handle_dump);
}
