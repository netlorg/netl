/*==============================================================================
| neta
|   code by Graham THE Ollis <ollisg@ns.arizona.edu>
|
| this code is (c) 1997 Graham THE Ollis
|
|  neta is network analysis software for analizing dumped ethernet frames.
|  your free to modify and distribute this program as long as this header is
|  retained, source code is made *freely* available and you document your 
|  changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  23 Feb 97  G. Ollis	.92 created network analysis software
|  28 Feb 97  G. Ollis	started using the net32 conversion for 32 bit integers
|			moved read() and dumpdata() to dump.c
|=============================================================================*/

char	*id = "@(#)neta (c) 1997 graham the ollis <ollisg@ns.arizona.edu>";

#include <stdio.h>
#include <stdlib.h>
#include "global.h"
#include "ether.h"
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
| globals
|=============================================================================*/

char *prog;
int noBackground;		/* this is a HACK */

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
  struct machdr *mac;
  size_t	offset = 14;

  mac = (struct machdr *) buff;

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
  struct iphdr		*ip = (struct iphdr *) buff;
  size_t		len = ip->ihl << 2;
  size_t		doff = len;

  puts("IP:");
  printf("  version:           %d\n", ip->version);
  printf("  header length:     %02x\n",len); 
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

  printf("  total length       %04x\n", net16(ip->tot_len));
  printf("  frag id            %04x\n", net16(ip->id));
  printf("  frag offset        %04x\n", net16(ip->frag_off));
  printf("  time to live       %02x\n", ip->ttl);
  fputs ("  protocol           ", stdout);

  switch(ip->protocol) {
    case PROTOCOL_TCP: 
      puts("tcp"); 
      printtcp(buff, len);
      doff += sizeof(struct tcphdr);
      printaddrport(buff, len);
      break;

    case PROTOCOL_UDP:
      puts("udp");
      printaddrport(buff, len);
      doff += sizeof(struct udphdr);
      break;

    case PROTOCOL_ICMP:
      puts("icmp");
      printaddr(buff);
      printicmp(buff, len);
      doff += sizeof(struct icmphdr);
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
  struct iphdr	*ip = (struct iphdr *) buff;
  struct udphdr	*udp = (struct udphdr *) &buff[len];

  printf("  %s:%d => %s:%d\n",
	ip2string(ip->saddr), net16(udp->source),
	ip2string(ip->daddr), net16(udp->dest));
}

/*==============================================================================
| printtcp
|=============================================================================*/

void
printtcp(u8 *buff, size_t len)
{
  struct tcphdr	*tcp = (struct tcphdr *) &buff[len];

  printf("  sequence number    %08x\n", net32(tcp->seq));
  printf("  ack number         %08x\n", net32(tcp->ack_seq));
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
  printf("  window size        %04x\n", net16(tcp->window));
  printf("  urg pointer        %04x\n", net16(tcp->urg_ptr));
}

/*==============================================================================
| printaddr
|=============================================================================*/

void
printaddr(u8 *buff)
{
  struct iphdr	*ip = (struct iphdr *) buff;

  printf("  %s => %s\n", ip2string(ip->saddr), ip2string(ip->daddr));
}

/*==============================================================================
| printicmp
|=============================================================================*/

void
printicmp(u8 *buff, size_t len)
{
  struct icmphdr	*icmp = (struct icmphdr *) &buff[len];
  int			i,n=0;

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

  printf("\n  id:                %04x\n", net16(icmp->un.echo.id));
  printf("  sequence:          %04x\n", net16(icmp->un.echo.sequence));
  printf("  gateway:           %08x\n", net32(icmp->un.gateway));
}  

