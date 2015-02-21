/*==============================================================================
| nm.c
|   coded by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
|   Copyright (C) 2001 White Dactyl Labs <ollisg@netl.org>
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

#ifndef NO_DLFCN_H
#include <dlfcn.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "netl/global.h"
#include "netl/io.h"
#include "netl/options.h"

#ifndef NO_SYSLOGD
#include <syslog.h>
#endif

/* this needs fixing too... */
typedef struct {
	void *dlmod;
	char *name;
} nm_t;

/*==============================================================================
| netl module open.
| + open the given module, run construct() if it exists and return the handle
|   to the new module.
|=============================================================================*/

int netl_nmopen_pretend = 0;

void *
netl_nmopen(char *name)
{
	void *handle;
	void (*f)(void);

	if(netl_nmopen_pretend) {	/* this is something different */

		FILE *fp;
		fp = fopen(name, "r");
		if(fp == NULL) {
			die(1, "could not (pretend to) load %s; reason:file does not exist", name);
		}
		fclose(fp);
		handle = allocate(strlen(name)+1);
		strcpy(handle, name);

	} else {

		#if BOOL_DYNAMIC_MODULES == 0
			handle = dlopen(name, 0);
		#else
			handle = dlopen(name, RTLD_NOW);
		#endif
		if(handle == NULL) {
			die(1, "could not load %s; reason:%s", name, dlerror());
		}

		f = dlsym(handle, "construct");
		if(f != NULL) 
			f();

	}

	return handle;
}


/*==============================================================================
| + call destroy()
| + deallocate the module.
|=============================================================================*/

int 
netl_nmclose(void *handle)
{
	void (*f)(void);

	if(netl_nmopen_pretend) {
		free(handle);
		return 0;
	}

	f = dlsym(handle, "destroy");
	if(f != NULL)
		f();

	return dlclose(handle);
}


/*==============================================================================
| wrapper around dlsym for netl modules.
|=============================================================================*/

void *
netl_nmsym(void *handle, char *symbol)
{
	void *sym;

	if(netl_nmopen_pretend)
		return NULL;

	sym = dlsym(handle, symbol);
	if(sym == NULL) {
		die(1, "could not resolve unknown::%s; reason:%s", symbol, dlerror());
	}
	return sym;
}

void *
netl_nmsym_nofail(void *handle, char *symbol)
{
	if(netl_nmopen_pretend)
		return NULL;

	return dlsym(handle, symbol);
}
