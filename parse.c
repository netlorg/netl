/*==============================================================================
| parse
|   parse a datagram and send the output to the right place.
|
|   optimized (and debugged) by Graham THE Ollis <ollisg@ns.arizona.edu>
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
|
|  Date       Name	Revision
|  ---------  --------  --------
|  26 sep 97  G. Ollis	took this code out of the main module and put it here
|			for safe keeping.
|=============================================================================*/

#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include "global.h"
#include "ether.h"
#include "ip.h"
#include "config.h"
#include "io.h"
#include "resolve.h"
#include "dcp.h"
#include "dgprintf.h"

/*==============================================================================
| globals
|=============================================================================*/

static u8 localhardware[6] = {0, 0, 0, 0, 0, 0};
static int logged=FALSE, dumped=FALSE; 
     /* don't want to log or dump more than once */

/*==============================================================================
| return the string or "" if it points to null
|=============================================================================*/

char *
string(char *s)
{
  if(s == NULL)
    return "";
  else
    return s;
}

/*==============================================================================
| dump ip datagram to disk
|=============================================================================*/

char *dgdump(u8 *dg, char *name, size_t len)
{
  static char	fn[1024];
  static int	sequence=0;
  FILE		*fp;

  sprintf(fn, "/tmp/netl/%s-%d-%d-%d.dg", 
              name, getpid(), (unsigned) time(NULL), sequence++);
  if((fp=fopen(fn, "w"))==NULL) {
    err("unable to open dump file %s", fn);
    return "error";
  }
  if(fwrite(dg, 1, len, fp) != len)
    err("error writing to dump file %s", fn);
  fclose(fp);
  return fn;
}

/*==============================================================================
| this is confusing because these are the conditions which must be
| FALSE in order for the functions below to continue.  much of this is generic
| but i want it to be fast (so i should be using __inline__ but am not).
|=============================================================================*/

#define all_packets \
       (c->action == ACTION_LOG && logged)			||\
       (c->action == ACTION_DUMP && dumped)			||\
       (c->action == ACTION_DL && dumped && logged)		||\
\
       (c->check_src_hw && !memcmp(c->src_hw, dg + 6, 6))	||\
       (c->check_dst_hw && !memcmp(c->dst_hw, dg, 6))		||\
       (c->check_src_hw_not && memcmp(c->src_hw_not, dg + 6, 6))||\
       (c->check_dst_hw_not && memcmp(c->dst_hw_not, dg, 6))

#define ip_packets \
       (c->check_src_ip && c->src_ip != ip.saddr)		||\
       (c->check_dst_ip && c->dst_ip != ip.daddr)		||\
       (c->check_src_ip_not && c->src_ip_not == ip.saddr)	||\
       (c->check_dst_ip_not && c->dst_ip_not == ip.daddr) 

#define tcp_and_udp_packets \
       (c->check_src_prt_not && c->src_prt_not == source)	||\
       (c->check_src_prt_not && c->dst_prt_not == dest)		||\
\
       (c->check_src_prt && (source < c->src_prt1 ||\
                              source > c->src_prt2))		||\
       (c->check_dst_prt && (dest < c->dst_prt1 ||\
                              dest > c->dst_prt2))

/*==============================================================================
| check/log raw
|=============================================================================*/

void
checkraw(u8 *dg, size_t len)
{
  int i;
  struct configitem *c;
  char *fn;

  for(i=0; i<raw_req.index; i++) {

    c = &raw_req.c[i];

    if(

       all_packets

      )
      continue;

    switch(c->action) {
      case ACTION_DL:
        fn=dgdump(dg, string(c->logname), len);
        if(c->format == NULL) 
          log(  "%s %02x:%02x:%02x:%02x:%02x:%02x =>"
                " %02x:%02x:%02x:%02x:%02x:%02x (%s)",
                string(c->logname),
		dg[6], dg[7], dg[8], dg[9], dg[10], dg[11],
		dg[0], dg[1], dg[2], dg[3], dg[4], dg[5],
                fn);
        else
          dgprintf(c->format, dg);
        logged = dumped = TRUE;
        break;

      case ACTION_LOG:
        if(c->format == NULL)
          log(  "%s %02x:%02x:%02x:%02x:%02x:%02x =>"
                " %02x:%02x:%02x:%02x:%02x:%02x",
                string(c->logname),
		dg[6], dg[7], dg[8], dg[9], dg[10], dg[11],
		dg[0], dg[1], dg[2], dg[3], dg[4], dg[5]);
        else
          dgprintf(c->format, dg);
        logged = TRUE;
        break;

      case ACTION_DUMP:
        dgdump(dg, string(c->logname), len);
        dumped = TRUE;
        break;

      case ACTION_IGNORE:
	return;

      default:
	break;
    }
  }
}

/*==============================================================================
| check/log ip
|=============================================================================*/

void
checkip(u8 *dg, iphdr ip, size_t len)
{
  int i;
  struct configitem *c;
  char *fn;

  for(i=0; i<ip_req.index; i++) {

    c = &ip_req.c[i];

    if(

       all_packets						||
       ip_packets

      )
      continue;

    switch(c->action) {
      case ACTION_DL:
        fn=dgdump(dg, string(c->logname), len);
        if(c->format == NULL) 
          log("%s %s => %s (%s)",
              string(c->logname),
              ip2string(ip.saddr),
              ip2string(ip.daddr),
              fn);
        else
          dgprintf(c->format, dg);
        logged = dumped = TRUE;
        break;

      case ACTION_LOG:
        if(c->format == NULL) 
          log(	"%s %s => %s",
                string(c->logname),
                ip2string(ip.saddr),
                ip2string(ip.daddr));
        else
          dgprintf(c->format, dg);
        logged = TRUE;
        break;

      case ACTION_DUMP:
        dgdump(dg, string(c->logname), len);
        dumped = TRUE;
        break;

      case ACTION_IGNORE:
	return;

      default:
	break;
    }
  }
}

/*==============================================================================
| check/log icmp
|=============================================================================*/

void
checkicmp(u8 *dg, iphdr ip, icmphdr *h, size_t len)
{
  int i;
  struct configitem *c;
  char *fn;

  for(i=0; i<icmp_req.index; i++) {

    c = &icmp_req.c[i];

    if(

       all_packets						||
       ip_packets						||

       /*=======================================================================
       | must be the correct type
       |======================================================================*/

       (c->check_icmp_type && c->icmp_type != h->type)		||
       (c->check_icmp_code && c->icmp_code != h->code)

      )
      continue;

    switch(c->action) {
      case ACTION_DL:
        fn=dgdump(dg, string(c->logname), len);
        if(c->format == NULL) 
          log(  "%s %s => %s (%s)",
                string(c->logname),
                ip2string(ip.saddr),
                ip2string(ip.daddr),
                fn);
        else
          dgprintf(c->format, dg);
        logged = dumped = TRUE;
        break;

      case ACTION_LOG:
        if(c->format == NULL) 
          log(	"%s %s => %s",
                string(c->logname),
                ip2string(ip.saddr),
                ip2string(ip.daddr));
        else
          dgprintf(c->format, dg);
        logged = TRUE;
        break;

      case ACTION_DUMP:
        dgdump(dg, string(c->logname), len);
        dumped = TRUE;
        break;

      case ACTION_IGNORE:
	return;

      default:
	break;
    }
  }
}

/*==============================================================================
| check/log tcp
|=============================================================================*/

void
checktcp(u8 *dg, iphdr ip, tcphdr *h, size_t len)
{
  int i;
  u8 flags=*(((char *) h) + 13);
  struct configitem *c;
  u16 source=ntohs(h->source), dest=ntohs(h->dest);
  char *fn;

  for(i=0; i<tcp_req.index; i++) {

    c = &tcp_req.c[i];

    if(

       all_packets						||
       ip_packets						||
       tcp_and_udp_packets					||

       /*=======================================================================
       | flags must be correct
       |======================================================================*/

       (c->check_tcp_flags_on && 
          (flags & c->tcp_flags_on) != c->tcp_flags_on)		||
       (c->check_tcp_flags_off && 
          (~flags & c->tcp_flags_off) != c->tcp_flags_off)

      )
      continue;

    switch(c->action) {
      case ACTION_DL:
        fn=dgdump(dg, string(c->logname), len);
        if(c->format == NULL) 
          log(  "%s %s:%d => %s:%d (%s)",
                string(c->logname),
                ip2string(ip.saddr),
		ntohs(h->source),
                ip2string(ip.daddr),
                ntohs(h->dest),
                fn);
        else
          dgprintf(c->format, dg);
        logged = dumped = TRUE;
        break;

      case ACTION_LOG:
        if(c->format == NULL) 
          log(	"%s %s:%d => %s:%d",
                string(c->logname),
                ip2string(ip.saddr),
		ntohs(h->source),
                ip2string(ip.daddr),
                ntohs(h->dest));
        else
          dgprintf(c->format, dg);
        logged = TRUE;
        break;

      case ACTION_DUMP:
        dgdump(dg, string(c->logname), len);
        dumped = TRUE;
        break;

      case ACTION_IGNORE:
	return;

      default:
        break;
    }
  }
}

/*==============================================================================
| check/log udp
|=============================================================================*/

void
checkudp(u8 *dg, iphdr ip, udphdr *h, size_t len)
{
  int i;
  struct configitem *c;
  u16 source=ntohs(h->source), dest=ntohs(h->dest);
  char *fn;

  /*============================================================================
  | check to see if this is a comunication request.
  | but first, check to see if we are even listening.
  |===========================================================================*/

  if(listenport != -1			&&	/* fast! */
     dest == listenport			&&	/* speedy! */
     ip.saddr == LOCALHOST_IP		&&	/* zap! */
     ip.daddr == LOCALHOST_IP		&&	/* zoom! */
     !memcmp(dg, localhardware, 6)	&&	/* kind of slow... */
     !memcmp(dg + 6, localhardware, 6))		/* sigh */
    hear(dg, h, len);

  /*============================================================================
  | process the datagram, even if it is a valid comunication request.
  |===========================================================================*/

  for(i=0; i<udp_req.index; i++) {

    c = &udp_req.c[i];

    if(

       all_packets						||
       ip_packets						||
       tcp_and_udp_packets

      )
      continue;

    switch(c->action) {
      case ACTION_DL:
        fn=dgdump(dg, string(c->logname), len);
        if(c->format == NULL) 
          log(	"%s %s:%d => %s:%d (%s)",
                string(c->logname),
                ip2string(ip.saddr),
		ntohs(h->source),
                ip2string(ip.daddr),
                ntohs(h->dest),
                fn);
	else
	  dgprintf(c->format, dg);
        logged = dumped = TRUE;
        break;

      case ACTION_LOG:
        if(c->format == NULL) 
          log(	"%s %s:%d => %s:%d",
                string(c->logname),
                ip2string(ip.saddr),
		source,
                ip2string(ip.daddr),
                dest);
	else
	  dgprintf(c->format, dg);
        logged = TRUE;
        break;

      case ACTION_DUMP:
        dgdump(dg, string(c->logname), len);
        dumped = TRUE;
        break;

      case ACTION_IGNORE:
	return;

      default:
	break;
    }
  }
}

/*==============================================================================
| void parsedg(u8 *buff);
|=============================================================================*/

void
parsedg(u8 *dg, size_t len)
{
  machdr	*mac = (machdr*) dg;
  iphdr		*ip = (iphdr*) &dg[14];

  logged = dumped = FALSE;

  /*============================================================================
  | check that this is a ip datagram.
  | check the version number.  should be ip version 4.
  |===========================================================================*/

  if(mac->type != MACTYPE_IPDG || ip->version != IP_VERSION) 
    return;

  /*============================================================================
  | locate the subprotocol header and point correct header pointer in the
  | right place.
  |===========================================================================*/

  switch(ip->protocol) {

    case PROTOCOL_UDP:
      checkudp(dg,
          *ip,
          (udphdr *) &dg[sizeof(machdr) + (ip->ihl << 2)],
          len);
      break;

    case PROTOCOL_ICMP:
      checkicmp(dg, 
          *ip,
          (icmphdr *) &dg[sizeof(machdr) + (ip->ihl << 2)],
          len);
      break;

    case PROTOCOL_TCP:
      checktcp(dg,
          *ip,
          (tcphdr *) &dg[sizeof(machdr) + (ip->ihl << 2)],
          len);
      break;

    default:
      checkip(dg, *ip, len);
      break;
  }

  /*============================================================================
  | all packets get checked as raw datagrams AFTER the subprotocols.
  |===========================================================================*/

  checkraw(dg, len);

}

