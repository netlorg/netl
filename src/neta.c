/*==============================================================================
| neta
|   code by Graham THE Ollis <ollisg@netl.org>
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

static char	*id = "@(#)neta (c) 1997 graham the ollis <ollisg@netl.org>";
static void dumb(char *c) { dumb(id); }

#include <stdio.h>
#include <stdlib.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/dump.h"
#include "netl/lookup.h"
#include "netl/options.h"
#include "netl/resolve.h"

/*==============================================================================
| prototypes
|=============================================================================*/

void print(u8 *, size_t);
size_t printip(u8 *);
void printaddrport(u8 *, size_t);
void printtcp(u8 *, size_t);
void printicmp(u8 *, size_t);
void printaddr(iphdr *);

/*==============================================================================
| main
| + this is the neta(1) main routine.  see the man page for details on its use.
|=============================================================================*/

int
main(int argc, char *argv[])
{
	int		i;
	u8		*buff;
	size_t	size;

	prog = argv[0];

	parsecmdline(argc, argv);
	if(displayVersion) {
		fputs("neta ", stdout);
		puts(COPYVER);
	}

	if(argc < 2) {
		fprintf(stderr, "usage: %s file [file ...]\n", prog);
		return 1;
	}

	for(i=1; i<argc; i++) {

		if(argv[i][0] == '-')
			continue;

		puts("-------------------------------------------------------------------");
		puts(argv[i]);
		if((buff = netl_io_readfile(argv[i], &size, 1500, prog)) != NULL) {
			print(buff, size);
			free(buff);
		} 
	}

	return 0;
}

/*==============================================================================
| print
|=============================================================================*/

void
print(u8 *buff, size_t size)
{
	machdr	*mac;
	size_t	offset = 14;

	mac = (machdr *) buff;

	puts("ethernet:");
	fputs("  type: ", stdout);

	if(mac->type == MACTYPE_IPDG)
		puts("IP datagram");
	else if(mac->type == MACTYPE_ARP)
		puts("ARP request/reply");
	else if(mac->type == MACTYPE_RARP)
		puts("RARP request/reply");
	else 
		printf("unknown [%04x]\n", mac->type);

	printf("  %02x:%02x:%02x:%02x:%02x:%02x => ",
	mac->src[0], mac->src[1], mac->src[2], 
	mac->src[3], mac->src[4], mac->src[5]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	mac->dst[0], mac->dst[1], mac->dst[2], 
	mac->dst[3], mac->dst[4], mac->dst[5]);

	if(mac->type == MACTYPE_IPDG) {
		offset += printip(buff + 14);
	}

	dumpdata(buff + offset, size - offset);
}

/*==============================================================================
| printip
|=============================================================================*/

size_t
printip(u8 *buff)
{
	iphdr		*ip = (iphdr *) buff;
	size_t	len = IPIHL(ip->ihl_version) << 2;
	size_t	doff = len;

	puts("IP:");
	printf("  version:           %d\n", IPVER(ip->ihl_version));
	printf("  header length:     %02x\n", (int) len); 
	fputs ("  type of service:   ", stdout);

	switch(ip->tos) {
		case 0x00: puts("none"); break;
		case 0x10: puts("minimize delay"); break;
		case 0x08: puts("maximize thruput"); break;
		case 0x04: puts("maximize reliability"); break;
		case 0x02: puts("minimize monitary cost"); break;
		default:
	printf("unknown [%02x]\n", ip->tos);
	break;
	}

	printf("  total length       %04x\n", ntohs(ip->tot_len));
	printf("  frag id            %04x\n", ntohs(ip->id));
	printf("  frag offset        %04x\n", ntohs(ip->frag_off));
	printf("  time to live       %02x\n", ip->ttl);
	fputs ("  protocol           ", stdout);

	switch(ip->protocol) {
		case PROTOCOL_TCP: 
			puts("tcp"); 
			printtcp(buff, len);
			doff += sizeof(tcphdr);
			printaddrport(buff, len);
			break;

		case PROTOCOL_UDP:
			puts("udp");
			printaddrport(buff, len);
			doff += sizeof(udphdr);
			break;

		case PROTOCOL_ICMP:
			puts("icmp");
			printaddr(ip);
			printicmp(buff, len);
			doff += sizeof(icmphdr);
			break;

		default:
			printf("unknown [%02x]\n", ip->protocol);
			//printaddr(buff);
			break;

	}  

	return doff;
}

/*==============================================================================
| printaddrport
|=============================================================================*/

void
printaddrport(u8 *buff, size_t len)
{
	iphdr	*ip = (iphdr *) buff;
	udphdr *udp = (udphdr *) &buff[len];

	printf("  %s:%d => %s:%d\n",
	ip2string(ip->saddr), ntohs(udp->source),
	ip2string(ip->daddr), ntohs(udp->dest));
}

/*==============================================================================
| printtcp
|=============================================================================*/

void
printtcp(u8 *buff, size_t len)
{
	tcphdr *tcp = (tcphdr *) &buff[len];

	printf("  sequence number    %08x\n", (u32) ntohl(tcp->seq));
	printf("  ack number         %08x\n", (u32) ntohl(tcp->ack_seq));
	printf("  doff               %x\n", tcp->doff << 2);
	fputs ("  flags              ", stdout);
	if(tcp->fin) 
		fputs("fin ", stdout);
	if(tcp->syn) 
		fputs("syn ", stdout);
	if(tcp->rst) 
		fputs("rst ", stdout);
	if(tcp->psh) 
		fputs("psh ", stdout);
	if(tcp->ack) 
		fputs("ack ", stdout);
	if(tcp->urg) 
		fputs("urg", stdout);
	putchar('\n');
	printf("  window size        %04x\n", ntohs(tcp->window));
	printf("  urg pointer        %04x\n", ntohs(tcp->urg_ptr));
}

/*==============================================================================
| printaddr
|=============================================================================*/

void
printaddr(iphdr *ip)
{
	//iphdr	*ip = (iphdr *) buff;

	printf("  %s => %s\n", ip2string(ip->saddr), ip2string(ip->daddr));
}

/*==============================================================================
| printicmp
|=============================================================================*/

void
printicmp(u8 *buff, size_t len)
{
	icmphdr	*icmp = (icmphdr *) &buff[len];
	int		i,n=0;

	fputs ("  type:              ", stdout);
	for(i=0; i<MAXICMPTYPE; i++) {
		if(icmptype[i].index == icmp->type) {
			puts(icmptype[i].name);
			n = 1;
			break;
		}
	}
	if(n == 0) {
		printf("unknown [%02x]\n", icmp->type);
	}

	printf("  code:              %02d ", icmp->code);
	for(i=0; i<MAXICMPCODE; i++) {
		if(icmpcode[i].index == icmp->code) {
			fputs(icmpcode[i].name, stdout);
			putchar(' ');
		}
	}

	printf("\n  id:                %04x\n", ntohs(icmp->un.echo.id));
	printf("  sequence:          %04x\n", ntohs(icmp->un.echo.sequence));
	printf("  gateway:           %08x\n", (u32) ntohl(icmp->un.gateway));
}  

