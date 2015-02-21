/*==============================================================================
| netl
|   optimized (and debugged) by Graham THE Ollis <ollisg@netl.org>
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

#define MAX 100
#define NULL 0
static struct {
	char *filename;
	char *symbolname;
	void *ptr;
} table[MAX];

static int count = 0;

void
register_symbols(void)
{
#include "in/simdl.h"
#include "filt/simdl.h"
#include "out/simdl.h"
}

void
register_symbol(char *fn, char *sm, void *p)
{
	if(count >= MAX) {
		exit(0);	/* this shouldn't ever happen, we hope :) */
	}
	table[count].filename = fn;
	table[count].symbolname = sm;
	table[count].ptr = p;
	count++;

	if(!strcmp(fn, NETL_INPUT_DEFAULT))
		register_symbol("in/default.so", sm, p);
}

static char *
check(const char *s1, const char *s2)
{
	char *x = (char *) s1;
	if(!*x)
		return NULL;
	do {
		if(!strcmp(s2, x)) {
			return x;
		}
		x++;
	} while(*x);
	return NULL;
}

static char *dlerror_str;

void *
dlopen(const char *filename, int flag)
{
	int i;
	char *tmp;

	for(i=0; i<count; i++) {
		if((tmp = check(filename, table[i].filename)) != NULL) {
			return (void*) tmp;
		}
	}
	dlerror_str = "could not file module";
	return NULL;
}

const char *
dlerror(void)
{
	return dlerror_str;
}

void *
dlsym(void *handle, char *symbol)
{
	int i;
	for(i=0; i<count && handle != NULL; i++) {
		if(!strcmp((char *)handle, table[i].filename) &&
		   !strcmp(symbol, table[i].symbolname))
			return table[i].ptr;
		
	}
	dlerror_str = "could not resolve symbol";
	return NULL;
}

int
dlclose(void *handle)
{
	/* uh... sure right, whatever */
	return 0;
}
