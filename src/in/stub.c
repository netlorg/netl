/*==============================================================================
| grab.c
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
|  26 sep 97  G. Ollis	took this code out of the main module.  this is all 
|			linux specific so far (ahh... there is a reason
|			go figure.)  all the networking code goes here.
|  04 apr 99  G. Ollis	this is now a stub for a input module for netl
|=============================================================================*/

#include <stdio.h>

#include "netl/global.h"
#include "netl/io.h"
#include "netl/ether.h"
#include "netl/grab.h"

fun_prefix int offset = 14; /* for ethernet, this is 14 */

/*==============================================================================
| prepare the ethernet card.  this usually involves putting the card in to
| promiscuious mode.
|=============================================================================*/

fun_prefix void
prepare(char *dev)
{
}

/*==============================================================================
| grab - grab the next packet that happens to pass by.
| return the size of the packet, returns -1 on error
|=============================================================================*/

fun_prefix int grab(char *buf)
{
	return 0;
}

#if BOOL_DYNAMIC_MODULES == 0
void
in_file_register_symbols(void)
{
	register_symbols("in/file.so", "prepare", prepare);
	register_symbols("in/file.so", "grab", grab);
}
#endif

