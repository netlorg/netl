/*==============================================================================
| resolve.h - ip => hostname resolution and cacheing functions
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@wwa.com>
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
==============================================================================*/

#ifndef RESOLVE_H
#define RESOLVE_H

/*==============================================================================
| prototypes
==============================================================================*/

char	*addip(const char *s, u32 ip);
char	*ip2string(u32 ip);
char	*search(u32 ip);
u32	searchbyname(char *);
void	clearipcache(void);
void	printalias(void);
void	alias_dump(FILE *fp);

#endif /* RESOLVE_H */
