/*==============================================================================
| hwlookup
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

static char	*id = "@(#)hwlookup by graham the ollis <ollisg@netl.org>";
static void dumb(char *d) { dumb(id); }	/* this avoids an anoying error msg */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifndef NO_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "netl/global.h"
#include "netl/options.h"
#include "netl/hwpassive.h"
#include "netl/resolve.h"
#include "netl/io.h"

typedef struct address_Entry {
	u8 addr[6];
	u8 bitmask[6];
	int flag;	/* TRUE if we are meant to NOT this entry */
	struct address_Entry *next;
} address_entry;

static address_entry *hws = NULL, *ips = NULL;
static int count = 0;

static int modifyip(u32 *num, char *name);
static int modifyhw(u8 *answer, u8* mask, char *name);
static void printentry(hwpassive_entry *e);

/*==============================================================================
| int main(int, char **)
| + main routine for hwlookup.  see the hwlookup(1) man page for detains on use.
|=============================================================================*/

int
main(int argc, char *argv[])
{
	FILE *fp;
	char *mask_s = NULL;
	int mask;
	int i, n;
	hwpassive_entry e;

	prog = argv[0];
	configfile = NETL_LIB_PATH "/hwpassive";

	//setservent(TRUE);
	parsecmdline(argc, argv); 
	if(displayVersion) {
		fputs("hwlookup ", stdout);
		puts(COPYVER);
	}

	for(i=1, n=0; i<argc; i++) {
		if(argv[i][0] != '-') {	/* it's not an option */
			char *ptr = argv[i];
			int flag = FALSE;

			mask = -1;
			mask_s = strrchr(ptr, '/');
			if(mask_s != NULL) {
				mask_s[0] = 0;
				mask_s++;
				mask = atoi(mask_s);
			}
			if(ptr[0] == '!') {
				flag = TRUE;
				ptr++;
			}

			if(!strcmp("all", ptr)) {
				u32 addr = 0;
				u32 addr_mask = 0;
				address_entry *tmp;
				tmp = allocate(sizeof(address_entry));
				memcpy((void *) tmp->addr, &addr, sizeof(u32));
				memcpy((void *) tmp->bitmask, &addr_mask, sizeof(u32));
				tmp->next = ips;
				ips = tmp;
				n++;
			} else if(strchr(ptr, ':') != NULL) { /* it's a hw address */
				u8 addr[6];
				u8 addr_mask[6] = {	0xff, 0xff, 0xff,
							0xff, 0xff, 0xff  };
				if(mask == -1)
					mask = 48;
				if(modifyhw(addr, addr_mask, ptr)) {
					address_entry *tmp = allocate(sizeof(address_entry));
					memcpy(tmp->addr, addr, 6);
					memcpy(tmp->bitmask, addr_mask, 6);
					tmp->flag = flag;
					tmp->next = hws;
					hws = tmp;
					n++;
				}


			} else {		/* otherwise, it's IP */
				u32 addr;
				u32 addr_mask = 0xffffffff;
				if(mask == -1)
					mask = 32;
				addr_mask = htonl(addr_mask << (32 - mask));
				if(mask == 0)
					addr_mask = 0;
				if(modifyip(&addr, ptr)) {
					address_entry *tmp;
					tmp = allocate(sizeof(address_entry));
					memcpy((void *) tmp->addr, &addr, sizeof(u32));
					memcpy((void *) tmp->bitmask, &addr_mask, sizeof(u32));
					tmp->flag = flag;
					tmp->next = ips;
					ips = tmp;
					n++;
				}

			}
		}
	}

	if(n == 0) {
		fprintf(stderr, "%s: no search criteria given, die\n", prog);
		return 0;
	}

	if(debug_mode) {
		while(ips != NULL) {
			printf("ip:%s/%08x\n", 
				ip2string(*((u32 *) ips->addr)),
				*((u32 *) ips->bitmask));
			ips = ips->next;
		}
		while(hws != NULL) {
			printf("hw:%02x:%02x:%02x:%02x:%02x:%02x",
				hws->addr[0], hws->addr[1], hws->addr[2],
				hws->addr[3], hws->addr[4], hws->addr[5]);
			printf("/%02x:%02x:%02x:%02x:%02x:%02x\n",
				hws->bitmask[0], hws->bitmask[1], hws->bitmask[2],
				hws->bitmask[3], hws->bitmask[4], hws->bitmask[5]);
			hws = hws->next;
		}
		return 0;
	}

	fp = fopen(configfile, "r");
	if(fp == NULL) {
		fprintf(stderr, "%s: error opening %s for read\n", prog, configfile);
		return 1;
	}

	while(fread(&e, sizeof(hwpassive_entry), 1, fp) == 1) {
		address_entry *tmp;
		int done = FALSE;
		u8 ip[4];
		memcpy(ip, &e.ip, 4);

		tmp = ips;
		while(tmp != NULL && !done) {
			int i, b=TRUE;
			//printf("************************\n");
			for(i=0; i<4; i++) {
				//printf("ip[%d] = %d\n", i, ip[i]);
				//printf("tmp->addr[%d] = %d\n", i, tmp->addr[i]);
				//printf("tmp->bitmask[%d] = %d\n", i, tmp->bitmask[i]);
				if(!	((ip[i] & tmp->bitmask[i]) ==
					 (tmp->addr[i] & tmp->bitmask[i]))
				  ) {
					b = FALSE;
				}
			}
			//printf("b = %d\n", b);
			//printf("tmp->falg = %d\n", tmp->flag);
			//printf("b ^ tmp->flag = %d\n", b ^ tmp->flag);
			//printf("************************\n");

			if(b ^ tmp->flag) {
				printentry(&e);
				done = TRUE;
			}
			tmp = tmp->next;
		}

		tmp = hws;
		while(tmp != NULL && !done) {
			int i, b=TRUE;
			for(i=0; i<6; i++) {
				if(!	((e.hw[i] & tmp->bitmask[i]) ==
					tmp->addr[i])
				  ) {
					b = FALSE;
				}
			}
			if(b) {
				printentry(&e);
				done = TRUE;
			}
			tmp = tmp->next;
		}
	}

	fclose(fp);

	if(hwlookup_mode == HWLOOKUP_COUNT)
		printf("%d\n", count);

	return 0;
}

static char *
time2str(time_t t)
{
        static char buffer[40];
        strcpy(buffer, ctime(&t));
        *strchr(buffer, '\n') = 0;
        return buffer;
}

static char *
time2str2(time_t t)
{
        static char buffer[40];
        strcpy(buffer, ctime(&t));
        *strchr(buffer, '\n') = 0;
        return buffer;
}

static char *
cardinfo(u8 *hw)
{
	FILE *fp;
	static char buffer[1026];
	char *num, *text=NULL;
	char tmp[3];

	fp = fopen(NETL_LIB_PATH "/hwcode", "r");
	if(fp == NULL)
		return "hwcode missing!";

	while(fgets(buffer, 1024, fp) != NULL) {
		int b = TRUE, n=0;
		num = strtok(buffer, ":\n");
		if(num != NULL && (text = strtok(NULL, ":\n")) != NULL) {
			while(num[0] != 0 && b) {
				u8 data;
				tmp[0] = num[0];
				tmp[1] = num[1];
				tmp[2] = 0;
				data = ahextoi(tmp);
				if(data != hw[n++])
					b= FALSE;
				num++;
				if(num[0] != 0)
					num++;
			}
			if(b)
				return text;
		}
	}
	return "unknown";
}

static void
printentry(hwpassive_entry *e)
{
		count++;
	if(hwlookup_mode == HWLOOKUP_SHORT) {
		printf("%02x:%02x:%02x:%02x:%02x:%02x => %s\n",
			e->hw[0], e->hw[1], e->hw[2], 
			e->hw[3], e->hw[4], e->hw[5],
			ip2string(e->ip));
	} else if(hwlookup_mode == HWLOOKUP_COUNT) {
	} else {
		printf(	"==============================================\n" 
			"HW:\t\t%02x:%02x:%02x:%02x:%02x:%02x\n"
			"IP:\t\t%s\n"
			"first seen:\t%s\n"
			"last seen:\t%s\n"
			"card info:\t%s\n",
			e->hw[0], e->hw[1], e->hw[2], 
			e->hw[3], e->hw[4], e->hw[5],
			ip2string(e->ip),
			time2str(e->first), time2str2(e->last),
			cardinfo(e->hw));
	}
}

static int
modifyhw(u8 *answer, u8 *mask, char *name)
{
	char *e;
	int i = 0;

	for(i=0; i<6; i++) {
		answer[i] = 0;
		mask[i] = 0;
	}

	e = strtok(name, ":"); i = 0;
	while(i < 6 && e != NULL) {
		mask[i] = 0xff;
		answer[i++] = ahextoi(e);
		e = strtok(NULL, ":");
	}

	return TRUE;
}

/*==============================================================================
| ip - stolen from config.y
|
|  this ... this is the most confusing piece of code i have ever seen in my
|  life.  i have no idea what it does, *exactly*  it... does a name lookup
|  or something odd, i can't quite figure out.  i certainly wish i had commented
|  it better when i wrote it, because i can't imagine what i was smoking when
|  i wrote it.  *shrug*
==============================================================================*/

static int
modifyip(u32 *num, char *name)
{
	u8	*tmp = (char *) num;
	char	*buff, *element;
	int	i=0;

	if((*num=searchbyname(name))!=0) {
		return TRUE;
	}

	buff = allocate(strlen(name) + 1);
	strcpy(buff, name);

	element = strtok(buff, ".");
		while(i < 4) {
			if(element == NULL) {

				fprintf(stderr, "warning: could not parse ip address %s\n",
					name);
				return FALSE;
			}
		tmp[i++] = atoi(element);
		element = strtok(NULL, ".");
	}

	return TRUE;
}

