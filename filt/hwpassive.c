/*==============================================================================
| hwpassive
|   passively listen for hardware addresses, keep a database of them,
|   and dump them to a file if we get the appropriate dcp(1) signal.
|
|   optimized (and debugged) by Graham THE Ollis <ollisg@wwa.com>
|
|   Copyright (C) 1999 Graham THE Ollis <ollisg@wwa.com>
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
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|  02 jul 99  G. Ollis	finally wrote this module, from a stub module.
|=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netl/global.h"

#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/resolve.h"

char *db_file = "/usr/local/lib/netl/hwpassive";

struct configlist req;

typedef struct Entry {		/* this should probably be a hash table instead */
	u8 hw[6];
	u32 ip;
	struct Entry *next;
} entry;

entry *db = NULL;
int updated = FALSE;

int
recurse(FILE *fp, entry *e)
{
	if(e==NULL)
		return TRUE;
	if(!recurse(fp, e->next))
		return FALSE;
	if(fwrite(e, sizeof(entry), 1, fp) == 0) {
		err("hwpassive: warning: error fwrite()");
		return FALSE;
	}
	return TRUE;
}

void
write_database()
{
	FILE *fp;
	log("hwpassive: writting database to file %s", db_file);
	fp = fopen(db_file, "w");
	if(fp == NULL) {
		err("hwpassive: warning: error writing to %s", db_file);
		return;
	} 
	recurse(fp, db);
	updated = TRUE;
	fclose(fp);
}

void 
destroy(void)
{
	if(updated) 
		write_database();
	else {
		log("hwpassive: warning: database is unchanged, will not write");
	}
}

void
construct(void)
{
	FILE *fp;
	entry *tmp;

	log("hwpassive: startup");
	atexit(destroy);
	fp=fopen(db_file, "r");
	if(fp == NULL) {
		log("hwpassive: no existing database, starting from scratch.");
	} else {
		log("hwpassive: existing database, reading.");
		tmp = allocate(sizeof(entry));
		while(fread(tmp, sizeof(entry), 1, fp) != 0) {
			/*log("read: %02x:%02x:%02x:%02x:%02x:%02x => %s",
				tmp->hw[0], tmp->hw[1], tmp->hw[2], tmp->hw[3], tmp->hw[4], tmp->hw[5], 
				ip2string(tmp->ip));*/
			tmp->next = db;
			db = tmp;
			tmp = allocate(sizeof(entry));
		}
		free(tmp);
	}
}

u8 hwbroadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
u8 hwloop[6] = { 0, 0, 0, 0, 0, 0 };

void
scan(u8 *hw, u32 ip)
{
	entry *tmp;
	u8 *tmp2;
	tmp = db;

	if(!memcmp(hw, hwbroadcast, 6) || !memcmp(hw, hwloop, 6))
		return;

	while(tmp != NULL) {
		if(!memcmp(hw, tmp->hw, 6)) {	/* we have a match! */
			if(ip == tmp->ip)	/* it's already there, don't need it. */
				return;
			tmp2 = (char *) &tmp->ip;
			log("found %02x:%02x:%02x:%02x:%02x:%02x => %u.%u.%u.%u in database (old)",
				hw[0], hw[1], hw[2], hw[3], hw[4], hw[5], 
				tmp2[0], tmp2[1], tmp2[2], tmp2[3]);
			break;
		}
		tmp = tmp->next;
	}
	updated = TRUE;
	tmp2 = (char *) &ip;
	log("adding %02x:%02x:%02x:%02x:%02x:%02x => %u.%u.%u.%u (%s)",
		hw[0], hw[1], hw[2], hw[3], hw[4], hw[5], 
		tmp2[0], tmp2[1], tmp2[2], tmp2[3], ip2string(ip));
	tmp = allocate(sizeof(entry));
	tmp->next = db;
	memcpy(tmp->hw, hw, 6);
	tmp->ip = ip;
	db = tmp;
}

/*==============================================================================
| check
|=============================================================================*/

static u32 lasthearid = 0;

void
check(u8 *dg, size_t len)
{
	machdr *mh = (machdr *) dg;
        iphdr *ip = (iphdr *) &dg[14];
	udphdr *h = (udphdr *) &dg[14 + (ip->ihl << 2)];
	int size, offset;
	u32 id;
	u16 nsize;
	char message[255];

        if(((machdr*)dg)->type != MACTYPE_IPDG)		/* although we are looking at raw data, it's completely useless, */
                return;					/* unless it has an IP address in it. */

        if(ip->version == 4) {
		scan(mh->src, ip->saddr);
		scan(mh->dst, ip->daddr);

		/* now, we check to see if this is a dcp packet */
	        if(ip->protocol != PROTOCOL_UDP || ntohs(h->dest) != 47 || 
			ip->saddr != LOCALHOST_IP || ip->daddr != LOCALHOST_IP)
                	return;

		if(memcmp(dg, hwloop, 6) || memcmp(&dg[6], hwloop, 6))
			return;

		offset = sizeof(machdr) + sizeof(iphdr) + sizeof(udphdr);

		id = ntohl(*((u32 *) &dg[offset]));             offset += 4;
		if(id == lasthearid)
			return;
		lasthearid = id;
		nsize = ntohs(*((u16 *) &dg[offset]));  offset += 2;

		size = len - offset;
		if(nsize < size)
			size = nsize;
		if(size > 254)
			size = 254;
		memcpy(message, &dg[offset], size);
			message[size] = '\0';

		if(!strcmp(message, "hwpassive:write")) {
			write_database();
		}
	}
}

