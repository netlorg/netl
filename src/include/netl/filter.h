/*==============================================================================
| filter.h - dynamic filter interface
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@netl.org>
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
==============================================================================*/

#ifndef NETL_FILTER_H
#define NETL_FILTER_H

typedef struct {
	void *handle;
	struct configlist *cf;
	void (*check)(u8 *, size_t, int);
	char *name;
	int filter_code;
} filt_mod;

extern filt_mod *filters;
extern int num_filters;

filt_mod *lookup_filter(char *, int);

#endif /* CONFIG_H */
