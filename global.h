/*==============================================================================
| global.h - macros everyone needs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>
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

#ifndef GLOBAL_H
#define GLOBAL_H

#ifndef linux
  #error netl requires linux
#endif

#define COPYVER "0.93 (c) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>"

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;

#ifndef TRUE
  #define TRUE			1
#endif
#ifndef FALSE
  #define FALSE			0
#endif

extern char *prog;

#endif /* GLOBAL_H */
