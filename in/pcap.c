/*==============================================================================
| pcap.c
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
|=============================================================================*/

#include <pcap.h>

/*==============================================================================
| prepare the ethernet card.  this usually involves putting the card in to
| promiscuious mode.
|=============================================================================*/

void
prepare(char *dev)
{
}

/*==============================================================================
| grab - grab the next packet that happens to pass by.
| return the size of the packet, returns -1 on error
|=============================================================================*/

int
grab(char *buf)
{
	return 0;
}

