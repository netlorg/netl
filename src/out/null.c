/*==============================================================================
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
|=============================================================================*/

#include "netl/global.h" 

#ifdef BOOL_THREADED
fun_prefix int action_done[PTHR_MAXTHREADS];
#else
fun_prefix int action_done;
#endif

/*==============================================================================
| stub
|=============================================================================*/

fun_prefix void
action(void *dg, void *cf, int len)
{
}

#if BOOL_DYNAMIC_MODULES == 0
void
out_null_register_symbols(void)
{
	register_symbol("out/null.so", "action_done", &action_done);
	register_symbol("out/null.so", "action", action);
}
#endif


