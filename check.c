/*==============================================================================
| parse
|   parse a datagram and send the output to the right place.
|
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
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"

/*==============================================================================
| void check();
| + given a packet *dg of length len, pass it to each of the filters.
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	int i;

	/*======================================================================
	| 1. reset the action_done flag in each output module
	|=====================================================================*/

	for(i=0; i<num_acts; i++) {
		*(acts[i]).action_done = FALSE;
	}

	/*======================================================================
	| 2. run check() from each filt module on the datagram
	|=====================================================================*/

	for(i=0; i<num_filters; i++) {
		(*filters[i].check)(dg, len);
	}
}

