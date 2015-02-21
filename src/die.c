/*==============================================================================
| die.c
|   code by Graham THE Ollis <ollisg@netl.org>
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
|=============================================================================*/

#include "netl/version.h"

#include <stdarg.h>
#include <stdio.h>
#ifndef NO_DLFCN_H
#include <dlfcn.h>
#endif

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/io.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "netl/filter.h"

static char *netl_death_message=NULL;

extern void *netl_guts_grab_module;

void netl_io_die(int retval, char *cp, ...)
{
	static char buff[2048] = "";
	va_list vararg;

	if(cp && *cp) {
		va_start(vararg, cp);
#ifdef NO_VSNPRINTF
		vsprintf(buff, cp, vararg);
#else
		vsnprintf(buff, 2040, cp, vararg);
#endif
		va_end(vararg);
	}

	netl_death_message = buff;

	#ifdef DIE_TRICKLE
	{
		int i;
		void (*dief)(int, char *);

		for(i=0; i<num_filters; i++) {
			dief = nmsym_nofail(filters[i].handle, "die");
			if(dief != NULL)
				dief(retval, netl_death_message);
		}

		for(i=0; i<num_acts; i++) {
			dief = nmsym_nofail(acts[i].handle, "die");
			if(dief != NULL)
				dief(retval, netl_death_message);
		}

		dief = nmsym_nofail(netl_guts_grab_module, "die");
		if(dief != NULL)
			dief(retval, netl_death_message);
	}
	#endif

	if(cp && *cp) 
		err(buff);
	exit(retval);
}
