/*==============================================================================
| parse.h
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
|=============================================================================*/

#ifndef PARSE_H
#define PRASE_H

char *string(char *s);
char *dgdump(u8 *dg, char *name, size_t len);
void checkicmp(u8 *dg, iphdr ip, icmphdr *h, size_t len);
void checktcp(u8 *dg, iphdr ip, tcphdr *h, size_t len);
void checkudp(u8 *dg, iphdr ip, udphdr *h, size_t len);
void parsedg(u8 *dg, size_t len);

#endif
