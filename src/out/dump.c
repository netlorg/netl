/*==============================================================================
| dump output module for netl
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

#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "netl/global.h"

#include "netl/action.h"
#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/options.h"

#ifdef BOOL_THREADED
fun_prefix int action_done[PTHR_MAXTHREADS];
#else
fun_prefix int action_done;
#endif

/*==============================================================================
| dump ip datagram to disk
|=============================================================================*/

fun_prefix char *
action(u8 *dg, struct configitem *cf, size_t len, int tid)
{
	static char	fn[1024];
	static int	sequence=0;
	FILE		*fp;

	#ifdef BOOL_THREADED
		action_done[tid] = TRUE;
	#else
		action_done = TRUE;
	#endif

	if(cf->logname != NULL) {
#ifdef NO_SNPRINTF
		sprintf(fn, "%s/%s-%d-%d-%d.dg", 
#else
		snprintf(fn, 1024, "%s/%s-%d-%d-%d.dg", 
#endif
			dump_dir,
			cf->logname, 
			getpid(), 
			(unsigned) time(NULL), 
			sequence++);
	} else {
		err("rule has no logname!");
#ifdef NO_SNPRINTF
		sprintf(fn, "%s/%d-%d-%d.dg", 
#else
		snprintf(fn, 1024, "%s/%d-%d-%d.dg", 
#endif
			dump_dir,
			getpid(), 
			(unsigned) time(NULL), 
			sequence++);
	}
	if((fp=fopen(fn, "w"))==NULL) {
		err("unable to open dump file %s", fn);
		return NULL;
	}
	if(fwrite(dg, 1, len, fp) != len)
		err("error writing to dump file %s", fn);
	fclose(fp);

	return fn;
}

#if BOOL_DYNAMIC_MODULES == 0
void
out_dump_register_symbols(void)
{
	register_symbol("out/dump.so", "action_done", &action_done);
	register_symbol("out/dump.so", "action", action);
}
#endif


