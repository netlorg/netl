/*==============================================================================
| hwpassive - passively listen to IP packets to keep track of hardware addresses
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

#ifndef HWPASSIVE_H
#define HWPASSIVE_H

#define MAX_COM_LEN 255

/*==============================================================================
| which "facility" should we send the syslog logs to?
==============================================================================*/

#define NETL_LOG_FACILITY	LOG_LOCAL4

/*==============================================================================
| prototypes
==============================================================================*/

int	netl(char *dev);
void	dgdump(u8 *dg, char *name, int len);
void	checkicmp(u8 *dg, struct iphdr ip, struct icmphdr *h, int len);
void	checktcp(u8 *dg, struct iphdr ip, struct tcphdr *h, int len);
void	checkudp(u8 *dg, struct iphdr ip, struct udphdr *h, int len);
void	parsedg(u8 *dg, int len);

#endif /* NETL_H */
