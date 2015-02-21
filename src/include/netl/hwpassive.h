/*==============================================================================
| hwpassive - passively listen to IP packets to keep track of hardware addresses
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

#ifndef NETL_HWPASSIVE_H
#define NETL_HWPASSIVE_H

#include <time.h>

extern int hwlookup_mode;

#define HWLOOKUP_LONG		0
#define HWLOOKUP_SHORT		1
#define HWLOOKUP_COUNT		2
#define HWLOOKUP_DEFAULT	HWLOOKUP_LONG

typedef struct hwpassive_Entry {
	u8 hw[6];
	u32 ip;
	time_t first, last;
	struct hwpassive_Entry *next;
} hwpassive_entry;

#endif /* HWPASSIVE_H */

