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

/* here are the functions which djgpp does not provide, that we need.  
there is probably a better way of doing this, but here it is... */

#include "netl/global.h"

struct hostent *
gethostbyname(const char *name)
{
	/* FIXME */
}

struct hostent *
gethostbyaddr(const char *addr, int len, int type)
{
	/* FIXME */
}
