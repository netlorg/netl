/*==============================================================================
| neta
|   code by Graham THE Ollis <ollisg@wwa.com>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  23 Feb 97  G. Ollis	.92 created network analysis software
|  28 Feb 97  G. Ollis	started using the net32 conversion for 32 bit integers
|			moved read() and dumpdata() to dump.c
|=============================================================================*/

char	*id = "@(#)neta (c) 1997 graham the ollis <ollisg@wwa.com>";

#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "dump.h"
#include "lookup.h"
#include "options.h"
#include "resolve.h"

/*==============================================================================
| prototypes
|=============================================================================*/

void print(u8 *buff, size_t size);
size_t printip(u8 *buff);
void printaddrport(u8 *buff, size_t len);
void printtcp(u8 *buff, size_t len);
void printicmp(u8 *buff, size_t len);
void printaddr(u8 *buff);

/*==============================================================================
| main
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
    if((buff = read(argv[i], &size, 1500, prog)) != NULL) {
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
  size_t	len = ip->ihl << 2;
  size_t	doff = len;

  puts("IP:");
  printf("  version:           %d\n", ip->version);
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
      printaddr(buff);
      printicmp(buff, len);
      doff += sizeof(icmphdr);
      break;

    default:
      printf("unknown [%02x]\n", ip->protocol);
      printaddr(buff);
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
printaddr(u8 *buff)
{
  iphdr	*ip = (iphdr *) buff;

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
    if(icmptype[i].index == icmp->type) {
      fputs(icmpcode[i].name, stdout);
      putchar(' ');
    }
  }

  printf("\n  id:                %04x\n", ntohs(icmp->un.echo.id));
  printf("  sequence:          %04x\n", ntohs(icmp->un.echo.sequence));
  printf("  gateway:           %08x\n", (u32) ntohl(icmp->un.gateway));
}  

