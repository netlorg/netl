/*==============================================================================
| io.c
|   optimized (and debugged) by Graham THE Ollis <ollisg@wwa.com>
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
|  28 Feb 97  G. Ollis	.92 created module
|  05 Mar 97  G. Ollis	.93 added ope so that all io comunication is handled
|			in this module.  syslog.h should not be handled in
|			any other module.  dump data is an exception to this
|			rule.  maybe some day i'll move that stuff in to here.
|			replaced putchar() with a couple of putc()s
|=============================================================================*/

#include <dlfcn.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "netl/global.h"
#include "netl/io.h"
#include "netl/options.h"

#ifndef NO_SYSLOGD
int noBackground = FALSE;
#endif

#ifndef NO_TEEOUT
FILE *teefile = NULL;
#endif

char *prog="[unassigned]";

/*==============================================================================
| log
|=============================================================================*/

void
log(char *cp,...)
{
	char buff[2048];	/* this should be enough memory */

	va_list vararg;
	if(cp && *cp) {
		va_start(vararg, cp);
		vsnprintf(buff, 2040, cp, vararg);
		va_end(vararg);
	}

#ifndef NO_SYSLOGD
	if(noBackground) {
#endif
		puts(buff);
#ifndef NO_TEEOUT
		if(teefile != NULL) {
			fputs(buff, teefile);
			fputc('\n', teefile);
			fflush(teefile);
		}
#endif
#ifndef NO_SYSLOGD
	} else {
		syslog(LOG_INFO, buff);
	}
#endif
}

void
err(char *cp,...)
{
	char buff[2048];	/* this should be enough memory */

	va_list vararg;
	if(cp && *cp) {
		va_start(vararg, cp);
		vsnprintf(buff, 2040, cp, vararg);
		va_end(vararg);
	}

#ifndef NO_SYSLOGD
	if(noBackground) {
#endif
		fputs(prog, stderr);
		putc(':', stderr);
		fputs(buff, stderr);
		putc('\n', stderr);
#ifndef NO_TEEOUT
		if(teefile != NULL) {
			fputs("error:", teefile);
			fputs(buff, teefile);
			fputc('\n', teefile);
			fflush(teefile);
		}
#endif
#ifndef NO_SYSLOGD
	} else
		syslog(LOG_ERR, buff);
#endif
}

/*==============================================================================
| allocate memory, and die if we don't have enough.
|=============================================================================*/

void *
allocate(size_t size)
{
	void *tmp;

	/*log("netl_allocate(%d)", size); */

	if((tmp = malloc(size)) == NULL) {
		err("error: could not malloc(), die");
		exit(2);
	}

	return tmp;
}

/*==============================================================================
| open syslog if necessary
| this is a little silly at the moment, but does serve to better modularize
| netl.
|=============================================================================*/

#ifndef NO_SYSLOGD
void
ope(char *s)
{
	if(!noBackground)
		openlog(s, 0, NETL_LOG_FACILITY);
}

void
clo()
{
	if(!noBackground)
		closelog();
}
#endif

void *
nmopen(char *name)
{
	void *handle;
	void (*f)(void);

	if(debug_mode)
		log("loading module: %s", name);

	handle = dlopen(name, RTLD_NOW);
	if(handle == NULL) {
		err("could not load %s; reason:%s", name, dlerror());
		exit(1);
	}

	f = dlsym(handle, "construct");
	if(f != NULL) 
		f();

	return handle;
}

int 
nmclose(void *handle)
{
	void (*f)(void);

	f = dlsym(handle, "destroy");
	if(f != NULL)
		f();

	return dlclose(handle);
}

void *
nmsym(void *handle, char *symbol)
{
	void *sym;

	sym = dlsym(handle, symbol);
	if(sym == NULL) {
		err("could not resolve unknown::%s; reason:%s", symbol, dlerror());
		exit(1);
	}
	return sym;
}

int
ahextoi(char *s)
{
	int val;

	for(val=0; *s; s++) {
		val *= 16;
		if('0' <= *s && *s <= '9') {
			val += (*s) - '0';
		} else if('A' <= *s && *s <= 'F') {
			val += (*s) - 'A' + 10;
		} else {
			val += (*s) - 'a' + 10;
		}
	}
	return val;
}
