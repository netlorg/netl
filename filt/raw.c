/*==============================================================================
| raw
|   parse a datagram 
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

#include "netl/global.h"

#include "netl/filter.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/action.h"
#include "netl/config.h"

#include "filt.h"

struct configlist req;

/*==============================================================================
| check raw
|=============================================================================*/

void
check(u8 *dg, size_t len)
{
	int i;
	struct configitem *c;

	for(i=0; i<req.index; i++) {

		c = &req.c[i];

		if(

			 all_packets

			)
			continue;

		act(dg, c, len);

	}
}
