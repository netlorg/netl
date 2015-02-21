/*==============================================================================
| dump.h - hex file dump routines used by neta and xd
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

#ifndef NETL_DUMP_H
#define NETL_DUMP_H

unsigned char *netl_io_readfile(char *fn, size_t *size, size_t max, char *prog);
void netl_io_dumpf(unsigned char *data, size_t size, FILE *fp);
#define dumpdata(data, size) netl_io_dumpf(data, size, stdout)
#define dumpdatafile(data, size, fp) netl_io_dumpf(data, size, fp)

#endif
