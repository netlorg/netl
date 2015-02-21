/*==============================================================================
| log/dump output module for netl
|   by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
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

#ifdef BOOL_THREADED
fun_prefix int action_done[PTHR_MAXTHREADS];
#else
fun_prefix int action_done;
#endif

void (*action_log)(u8 *, struct configitem *, size_t);
char **extra_string;
char *(*action_dump)(u8 *, struct configitem *, size_t);
void *handle_log, *handle_dump;

/*==============================================================================
| dump ip datagram to disk
|=============================================================================*/

fun_prefix void
action(u8 *dg, struct configitem *cf, size_t len, int tid)
{
	*extra_string = action_dump(dg, cf, len);
	action_log(dg, cf, len);
	*extra_string = "";
	#ifdef BOOL_THREADED
		action_done[tid] = 1;
	#else
		action_done = 1;
	#endif
}

/*==============================================================================
| constructor
|=============================================================================*/

static int semaphore = 0;

fun_prefix void
construct(void)
{
	char buffer[255];

	semaphore++;
	if(semaphore != 1)
		return;

#ifdef NO_SNPRINTF
	sprintf(buffer, "%s/out/log.so", netl_config_so_path);
#else
	snprintf(buffer, 255, "%s/out/log.so", netl_config_so_path);
#endif
	handle_log = nmopen(buffer);

	action_log = nmsym(handle_log, "action");
	extra_string = nmsym(handle_log, "extra_string");

#ifdef NO_SNPRINTF
	sprintf(buffer, "%s/out/dump.so", netl_config_so_path);
#else
	snprintf(buffer, 255, "%s/out/dump.so", netl_config_so_path);
#endif
	handle_dump = nmopen(buffer);

	action_dump = nmsym(handle_dump, "action");
	if(action_dump == NULL) {
		die(1, "could not resolve necessary sysmbols in %s!", buffer);
	}

}

/*==============================================================================
| destructor
|=============================================================================*/

fun_prefix void
destroy(void)
{
	semaphore--;
	if(semaphore != 0)
		return;
	nmclose(handle_log);
	nmclose(handle_dump);
}


#if BOOL_DYNAMIC_MODULES == 0
void
out_dl_register_symbols(void)
{
	register_symbol("out/dl.so", "action_done", &action_done);
	register_symbol("out/dl.so", "action", action);
	register_symbol("out/dl.so", "construct", construct);
	register_symbol("out/dl.so", "destroy", destroy);
}
#endif


