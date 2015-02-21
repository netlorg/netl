/*==============================================================================
| config.c
|   read config file for netl
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
|  23 Feb 97  G. Ollis	created module
|  25 Feb 97  G. Ollis	.91 added port range support
|  05 Mar 97  G. Ollis	.93 added listen option for run time comunication.
|  09 Mar 97  G. Ollis	default value for .logname is now NULL
|			(note changes in netl.c also)
|  03 Jun 97  G. Ollis	added `detect' config line to make configeration
|			just a little less necessary.
|=============================================================================*/

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>

#include "global.h"
#include "ether.h"
#include "ip.h"

#include "config.h"
#include "resolve.h"
#include "lookup.h"
#include "io.h"
#include "options.h"

/*==============================================================================
| this swap is a bit of a haxor as we say in the old school
| if the compiler is smart, this will be really fast, and require
| no temp variable.  this works only for integers of any native size.
==============================================================================*/

#define swap(x, y)	x ^= y;\
			y ^= x;\
			x ^= y;

/*==============================================================================
| globals
==============================================================================*/

int line=0;
struct configlist icmp_req, tcp_req, udp_req, raw_req, ip_req;
signed int listenport = -1;	/* oh my gosh, i'm wasting 15 BITS!!!! */
int configmax = 0;

/*==============================================================================
| clean up all the config data and make it ready for a new config file read.
==============================================================================*/

static void
freelist(struct configlist *cl)
{
  int i;
  for(i=0; i<cl->index; i++) {
    if(cl->c[i].logname != NULL)
      free(cl->c[i].logname);
    if(cl->c[i].format != NULL)
      free(cl->c[i].format);
  }
  free(cl->c);
  cl->c = NULL;
}

void
clearconfig()
{
  freelist(&icmp_req);
  freelist(&tcp_req);
  freelist(&udp_req);
  freelist(&raw_req);
  freelist(&ip_req);
}

/*==============================================================================
| copyname
==============================================================================*/

static char *
copyname(char *s) 
{
  char *tmp = (char *) allocate(strlen(s) + 1);
  return strcpy(tmp, s);
}

/*==============================================================================
| getportnum
==============================================================================*/

static u16
getportnum(char *s, u8 prot)
{
  int			i;
  struct servent	*service;

  i=atoi(s);
  if(i != 0)
    return i;

  if(prot == PROTOCOL_TCP) 
    service = getservbyname(s, "tcp");
  else if(prot == PROTOCOL_UDP)
    service = getservbyname(s, "udp");
  else
    return 0;

  if(service == NULL)
    return 0;
  else
    return ntohs(service->s_port);
}

/*==============================================================================
| port
==============================================================================*/

static int
modifyport(u16 *num1, u16 *num2, char *name1, u8 prot)
{
  char *name2 = strchr(name1, '-');

  if(num2 != NULL) {

    if(name2 != NULL) {
      *(name2++) = 0;
      if((*num1 = getportnum(name1, prot)) && 
         (*num2 = getportnum(name2, prot))) {

        if(*num2 < *num1) 
          swap(*num1, *num2);

        return TRUE;
      }
      err("warning: unknown port range %s-%s (line %d)",
		name1, name2, line);
      return FALSE;
    }
  }

  if((*num1 = getportnum(name1, prot)) !=0) {
    if(num2 != NULL)
      *num2 = *num1;
    return TRUE;
  }

  err("warning: unknown port %s (line %d)", name1, line);
  return FALSE;
}

/*==============================================================================
| mac address
==============================================================================*/

static int
modifyhw(u8 *output, char *input)
{
  u8 tmp[12];
  int i;
  char *full;

  i=0;
  memset(tmp, 0, 12);
  full = input;

  while(*input && i<12) {

    if(*input >= '0' && *input <= '9')
      tmp[i++] = *input - '0';

    if(*input >= 'a' && *input <= 'f')
      tmp[i++] = *input - 'a' + 10;

    if(*input >= 'A' && *input <= 'F')
      tmp[i++] = *input - 'A' + 10;

    input++;
  }

  if(*input != 0) {
    err("warning hw address is too long %s (%d)", full, line);
  }

  if(i!=12) {
    err("warning hw address is too short %s (%d)", full, line);
  }

  for(i=0; i<6; i++)
    output[i] = tmp[i*2] << 4 | tmp[i*2+1];

/*  fprintf(stderr, "modifyhw(): %2x:%2x:%2x:%2x:%2x:%2x\n",
		output[0], output[1], output[2],
		output[3], output[4], output[5]);*/

  return TRUE;
}

/*==============================================================================
| ip
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
      err("warning: could not parse ip address %s (line %d)",
		name, line);
      return FALSE;
    }
    tmp[i++] = atoi(element);
    element = strtok(NULL, ".");
  }

  return TRUE;
}

/*==============================================================================
| icmp - that stands for I Can Mess with People.  (for those of you who 
| believe icmp was designed to nuke win32 boxes)
==============================================================================*/

static int
modifyicmp(u8 *item, char *name, struct lookupitem *l, int size)
{
  int i;

  i = atoi(name);
  if(name[0] == '0' || i != 0) {
    *item = i;
    return TRUE;
  }

  for(i=0; i<size; i++) {
    if(!strcmp(l[i].name, name)) {
      *item = l[i].index;
      return TRUE;
    }
  }

  err("warning: unknown icmp %s (line %d)", name, line);

  return FALSE;
}

/*==============================================================================
| TCP flags
==============================================================================*/

static int
modifyflags(flagbyte *fb, u8 other, char *name)
{
  char	*tmp;
  u8	*tmp2 = (u8 *) fb;

  tmp = strtok(name, ",");
  while(tmp != NULL) {

    if(!strcmp(tmp, "urg"))
      fb->urg = TRUE;
    else if(!strcmp(tmp, "ack"))
      fb->ack = TRUE;
    else if(!strcmp(tmp, "psh"))
      fb->psh = TRUE;
    else if(!strcmp(tmp, "rst"))
      fb->rst = TRUE;
    else if(!strcmp(tmp, "syn"))
      fb->syn = TRUE;
    else if(!strcmp(tmp, "fin"))
      fb->fin = TRUE;
    else if(!strcmp(tmp, "all"))
      *tmp2 = ~other;
    else if(!strcmp(tmp, "none"))
      *tmp2 = 0;
    else
      err("warning: unknown tcp flag %s (line %d)", tmp, line);

    tmp = strtok(NULL, ",");
  }

  fb->reserved = 0;
  return TRUE;
}

/*==============================================================================
| set initial list size
==============================================================================*/

static void
setlist(struct configlist *l)
{
  l->c=(struct configitem *) allocate(sizeof(struct configitem)*100);
  l->size = 100;
  l->index = 0;
}

/*==============================================================================
| resize config list
==============================================================================*/

static void
resizelist(struct configlist *l, int size)
{
  struct configitem *tmp;
  size_t memorysize;

  if(l->size == size)	/* you want me to do what? */
    return;

  memorysize = sizeof(struct configitem) * size;

  tmp=(struct configitem *) allocate(memorysize);

  memcpy(tmp, l->c, memorysize);
  free(l->c);
  l->c = tmp;
  l->size = size;
}

/*==============================================================================
| detect hostname/IP number
==============================================================================*/

void
detectf()
{
  char			buff[255];
  struct hostent *	herhost;
  union			{ u32 i; u8 c[4]; } addr;

  addip("localhost", LOCALHOST_IP);
  addr.i = searchbyname("localhost");
  gethostname(buff, 255);
  if((herhost = gethostbyname(buff)) != NULL) {
    addip("local", *((u32 *) herhost->h_addr_list[0]) );
    addip(buff, *((u32 *) herhost->h_addr_list[0]) );
  } else {
    err("warning: could not detect hostname");
  }
}

/*==============================================================================
| add an item
==============================================================================*/

static void
additem(struct configlist *l, struct configitem *c)
{
  if(l->index == l->size)
    resizelist(l, l->size * 2);

  memcpy((char *) &l->c[l->index++], (char *) c, sizeof(struct configitem));
}

/*==============================================================================
| get rid of a single character in a string.
==============================================================================*/

#define ridstring(s) memmove(s, s+1, strlen(s));

/*==============================================================================
| tokenize a config line.  strtok is no longer adiquete.
| returns the number of tokens
==============================================================================*/

int
tokenize(char **tokens, char *input)
{
  int inws = TRUE;
  int i = 0; 

  while(input != NULL && *input != 0 && i < NETL_CONFIG_MAXTOKENS) {

    /*==========================================================================
    | replace white space with the null character
    ==========================================================================*/

    if(*input == ' ' || *input == '\n' || *input == '\t') {
      *(input++) = 0;
      inws = TRUE;
    } else {

      /*========================================================================
      | other
      ========================================================================*/

      if(inws) {
        tokens[i++] = input++;
        inws = FALSE;
      } else {
        input++;
      }

      /*========================================================================
      | skip over any white space in a quoted string
      ========================================================================*/

      if(*input == '\"') {
        ridstring(input);
        if((input = strchr(input, '\"')) == NULL) {
          err("warning: non-terminated string on line %d.\n", line);
        } else if(*input == '\"')
          ridstring(input);
      } 
    }
  }

  return i;
}

/*==============================================================================
| parse a single config line
==============================================================================*/

void
parseconfigline(char *buff)
{
  char		*tokens[NETL_CONFIG_MAXTOKENS];
  int		i,n;
  u32		tmp;
  struct configitem
		citem;

    /*==========================================================================
    | tokenize the config line 
    ==========================================================================*/

/*    tokens[0] = strtok(buff, "\t\n ");
    i = 0;
    while(tokens[i] != NULL && i<NETL_CONFIG_MAXTOKENS) 
      tokens[++i] = strtok(NULL, "\t\n ");*/
    i = tokenize(tokens, buff);

    /*==========================================================================
    | blank line, go to the next one
    ==========================================================================*/

    if(i == 0)
      return;

    /*==========================================================================
    | detect instructs netl to try and figure out the local host name itself.
    | no arguments for this config line.
    ==========================================================================*/

    if(!strcmp(tokens[0], "detect")) {
      detectf();
      return;
    }

    /*==========================================================================
    | device allows you to specify an alternate device.  for the moment, only
    | ethernet is supported so don't bother using anything other than eth0,
    | eth1... etc.
    ==========================================================================*/

    if(!strcmp(tokens[0], "device")) {
      if(tokens[1] == NULL) 
        return;
      strncpy(netdevice, tokens[1], 255);
      return;
    }

    /*==========================================================================
    | listen allows a sysadmin to have netl listen to communication from the
    | local machine.  this is potentially dangerous, but also helpful if you
    | want to have netl reread the config file while it is already running.
    ==========================================================================*/

    if(!strcmp(tokens[0], "listen")) {
      if(i < 2) {
        listenport = 47;	/* my favorite default value */
      } else {
        listenport = atoi(tokens[1]);
        if(listenport == 0) {
          err("warning: %s is not a valid port, comunication off.", tokens[1]);
          listenport = -1;	/* probably unnecessary */
          return;
        }
      }
      log("listening to port %d", listenport);
      return;
    }

    if(i < 3) {
      err("warning: %d args, bad config line (line %d)", i, line);
      return;
    }

    if(!strcmp(tokens[0], "port")) {
      return;
    }

    if(!strcmp(tokens[0], "alias")) {
      modifyip(&tmp, tokens[2]);
      addip(tokens[1], tmp);
      return;
    }

    memset(&citem, 0, sizeof(struct configitem));

    /*==========================================================================
    | check the action field.  this should be one of:
    |  * log the given item should be logged using syslog
    |  * dump the given item should be dumped to a file in /tmp/netl/
    |  * ignore the given item should be ignored, and no further rules should
    |    be checked.
    |  * dl - dump and log
    ==========================================================================*/

    if(!strcmp(tokens[0], "log"))
      citem.action = ACTION_LOG;
    else if(!strcmp(tokens[0], "dump"))
      citem.action = ACTION_DUMP;
    else if(!strcmp(tokens[0], "ignore"))
      citem.action = ACTION_IGNORE;
    else if(!strcmp(tokens[0], "dl"))
      citem.action = ACTION_DL;
    else {
      err("warning: unknown action %s (line %d)", tokens[0], line);
      return;
    }

    /*==========================================================================
    | next field is the protocol field.  this should be one of:
    |  * tcp
    |  * udp
    |  * icmp
    ==========================================================================*/

    if(!strcmp(tokens[1], "tcp")) 
      citem.protocol = PROTOCOL_TCP;
    else if(!strcmp(tokens[1], "icmp"))
      citem.protocol = PROTOCOL_ICMP;
    else if(!strcmp(tokens[1], "udp")) 
      citem.protocol = PROTOCOL_UDP;
    else if(!strcmp(tokens[1], "raw"))
      citem.protocol = PROTOCOL_RAW;
    else if(!strcmp(tokens[1], "ip"))
      citem.protocol = PROTOCOL_IP;
    else {
      err("warning: unknown protocol %s (line %d)", tokens[1], line);
      return;
    }

    /*==========================================================================
    | any remaining fields are restriction fields
    |
    | name=		syslog name
    |
    | format=		to use an alternate log format.  this effects
    |			log and dl only
    |
    | flag=		TCP flags that must be set (all=!flagoff)
    | !flag=		TCP flags that must be unset (all=!flagon)
    |   * urg
    |   * ack
    |   * psh
    |   * rst
    |   * syn
    |   * fin
    |
    | dstport=		TCP/UDP ports
    | srcport=
    |
    | dstip=		IP numbers in dotted decimal
    | srcip=
    |
    | dsthw=		MAC addresses (with optional colons)
    | srchw=
    |
    | type=		icmp type
    | code=		icmp code
    ==========================================================================*/

    citem.logname = NULL;
    citem.format = NULL;

    for(n=2; n<i; n++) {

      /*========================================================================
      | name=
      ========================================================================*/

      if(!strncmp(tokens[n], "name=", 5)) {
        if(citem.logname != NULL)
          free(citem.logname);
        citem.logname = copyname(tokens[n] + 5);
      }

      /*========================================================================
      | format=
      ========================================================================*/

      else if(!strncmp(tokens[n], "format=", 7)) {
        if(citem.format != NULL)
          free(citem.format);
        citem.format = copyname(tokens[n] + 7);
      }

      /*========================================================================
      | ports
      ========================================================================*/
      
      else if(!strncmp(tokens[n], "dstport=", 8)) {
        citem.check_dst_prt = modifyport(
		&citem.dst_prt1,
		&citem.dst_prt2,
		tokens[n] + 8,
		citem.protocol);
      }
      else if(!strncmp(tokens[n], "!dstport=", 9)) {
        citem.check_dst_prt_not = modifyport(
		&citem.dst_prt_not,
		NULL,
		tokens[n] + 9,
		citem.protocol);
      }
      else if(!strncmp(tokens[n], "srcport=", 8)) {
        citem.check_src_prt = modifyport(
		&citem.src_prt1,
		&citem.src_prt2,
		tokens[n] + 8,
		citem.protocol);
      }
      else if(!strncmp(tokens[n], "!srcport=", 9)) {
        citem.check_src_prt_not = modifyport(
		&citem.src_prt_not,
		NULL,
		tokens[n] + 9,
		citem.protocol);
      }

      /*========================================================================
      | MAC addresses
      ========================================================================*/

      else if(!strncmp(tokens[n], "dsthw=", 6)) {
        citem.check_dst_hw = modifyhw(
               citem.dst_hw,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!dsthw=", 7)) {
        citem.check_dst_hw_not = modifyhw(
               citem.dst_hw_not,
               tokens[n] + 7);
      }
      else if(!strncmp(tokens[n], "srchw=", 6)) {
        citem.check_src_hw = modifyhw(
               citem.src_hw,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!srchw=", 7)) {
        citem.check_src_hw_not = modifyhw(
               citem.src_hw_not,
               tokens[n] + 7);
      }

      /*========================================================================
      | IP addresses
      ========================================================================*/

      else if(!strncmp(tokens[n], "dstip=", 6)) {
        citem.check_dst_ip = modifyip(
               &citem.dst_ip,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!dstip=", 7)) {
        citem.check_dst_ip_not = modifyip(
               &citem.dst_ip_not,
               tokens[n] + 7);
      }

      else if(!strncmp(tokens[n], "srcip=", 6)) {
        citem.check_src_ip = modifyip(
               &citem.src_ip,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!srcip=", 7)) {
        citem.check_src_ip_not = modifyip(
               &citem.src_ip_not,
               tokens[n] + 7);
      }

      /*========================================================================
      | ICMP stuff
      ========================================================================*/

      else if(!strncmp(tokens[n], "type=", 5)) {
        citem.check_icmp_type = modifyicmp(
		&citem.icmp_type,
		tokens[n] + 5,
		icmptype,
		MAXICMPTYPE);
      }
      else if(!strncmp(tokens[n], "code=", 5)) {
        citem.check_icmp_type = modifyicmp(
		&citem.icmp_type,
		tokens[n] + 5,
		icmpcode,
		MAXICMPCODE);
      }

      /*========================================================================
      | TCP flags
      ========================================================================*/

      else if(!strncmp(tokens[n], "flag=", 5)) {
        citem.check_tcp_flags_on = modifyflags(
		(flagbyte *) &citem.tcp_flags_on, 
		citem.tcp_flags_off,
		tokens[n] + 5);
      } 
      else if(!strncmp(tokens[n], "!flag=", 6)) {
        citem.check_tcp_flags_off = modifyflags(
		(flagbyte *) &citem.tcp_flags_off, 
		citem.tcp_flags_on,
		tokens[n] + 6);
      } 

      /*========================================================================
      | unknown
      ========================================================================*/

      else {
        err("warning: unknown requirement %s (line %d)", tokens[n], line);
      }
    }

    /*==========================================================================
    | store the requirement in the correct config array.
    ==========================================================================*/

    switch(citem.protocol) {
      case PROTOCOL_TCP:
	additem(&tcp_req, &citem);
        break;

      case PROTOCOL_UDP:
	additem(&udp_req, &citem);
        break;

      case PROTOCOL_ICMP:
	additem(&icmp_req, &citem);
        break;

      case PROTOCOL_RAW:
        additem(&raw_req, &citem);
        break;

      case PROTOCOL_IP:
        additem(&ip_req, &citem);

      default:
	break;
    }

}

/*==============================================================================
| what happens before and after you do the config stuff.
==============================================================================*/

void
preconfig()
{
  setlist(&icmp_req);
  setlist(&tcp_req);
  setlist(&udp_req);
  setlist(&raw_req);
  setlist(&ip_req);
}

void
postconfig()
{
  resizelist(&icmp_req, icmp_req.index);
  resizelist(&tcp_req, tcp_req.index);
  resizelist(&udp_req, udp_req.index);
  resizelist(&raw_req, raw_req.index);
  resizelist(&ip_req, ip_req.index);
}

/*==============================================================================
| getline(char *buff, int max, FILE *fp)
==============================================================================*/

char *
getline(char *buff, int max, FILE *fp)
{
  int i=0;
  int doloop=FALSE;

  line++;

  if(feof(fp))
    return NULL;

  do {

    for(i=0; i<max && !feof(fp) && (buff[i]=fgetc(fp)) != '\n'; i++)
      ;

    if(i==max-1) {
      err("warning: long config %d line cut.\n", line);
      while(!feof(fp) && fgetc(fp) != '\n')
        ;
      buff[i] = 0;
      return buff;
    }

    if(feof(fp)) {
      buff[--i] = 0;
      return buff;
    }

    if(i>=1 && buff[i-1] == '\\') 
      doloop = TRUE;

  } while(doloop);

  buff[i] = 0;

  return buff;
}

/*==============================================================================
| readconfig(char *prog)
|
|  this function reads the config file and alters the config structure
|  apropriately
==============================================================================*/

#ifdef NO_SYSLOGD
void
readconfig(char *confname)
#endif
#ifndef NO_SYSLOGD
void
readconfig(char *confname, int nbg)
#endif
{
  FILE		*fp;
  char		buff[NETL_CONFIG_MAXWIDTH];
  int		i;

#ifndef NO_SYSLOGD
  swap(nbg, noBackground);
#endif

  if((fp=fopen(confname, "r")) == NULL) {             /* open, damn it, open */
    err("error: opening %s for read, die", confname); /* magnus, i want the 
							 matrix. */
    exit(2);					      /* NEVER! */
  }

  line = 1;

  while(getline(buff, NETL_CONFIG_MAXWIDTH, fp) != NULL) {

    /* skip comment lines */
    if(buff[0] == '#') 
      continue;

    for(i=0; buff[i]; i++) {
      if(buff[i] == '#') {
        buff[i] = 0;
        break;
      }
    }

    parseconfigline(buff);

  }

  line = 0;

#ifndef NO_SYSLOGD
  swap(nbg, noBackground);
#endif

  endservent();
}

/*==============================================================================
| printconfig - print out config options as a debugging option thing.
==============================================================================*/

void
printconfig()
{
  int i;
  struct configitem *c;

  for(i=0; i<icmp_req.index; i++) {
    c = &icmp_req.c[i];
    switch(c->action) {
      case ACTION_NONE   : fputs("none\t", stdout); break;
      case ACTION_LOG    : fputs("log\t",  stdout); break;
      case ACTION_DUMP   : fputs("dump\t", stdout); break;
      case ACTION_IGNORE : fputs("ignore\t", stdout); break;
      case ACTION_DL     : fputs("dl\t", stdout); break;
      default : printf("unknown(%u) ", c->action); break;
    }
    fputs("icmp\t", stdout);

    if(c->logname != NULL)
      printf("name=%s ", c->logname);
    if(c->format != NULL)
      printf("format=\"%s\" ", c->format);
    if(c->check_icmp_type)
      printf("type=%u ", c->icmp_type);
    if(c->check_icmp_code)
      printf("code=%u ", c->icmp_code);

    if(c->check_src_ip)
      printf("srcip=%s ", ip2string(c->src_ip));
    if(c->check_dst_ip)
      printf("dstip=%s ", ip2string(c->dst_ip));

    if(c->check_src_ip_not)
      printf("!srcip=%s ", ip2string(c->src_ip_not));
    if(c->check_dst_ip_not)
      printf("!dstip=%s ", ip2string(c->dst_ip_not));

    if(c->check_src_hw)
      printf("srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw[0], c->src_hw[1],
                                         c->src_hw[2], c->src_hw[3],
					 c->src_hw[4], c->src_hw[5]);
    if(c->check_dst_hw)
      printf("dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw[0], c->dst_hw[1],
                                         c->dst_hw[2], c->dst_hw[3],
					 c->dst_hw[4], c->dst_hw[5]);
    if(c->check_src_hw_not)
      printf("!srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw_not[0], c->src_hw_not[1],
                                         c->src_hw_not[2], c->src_hw_not[3],
					 c->src_hw_not[4], c->src_hw_not[5]);
    if(c->check_dst_hw_not)
      printf("!dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw_not[0], c->dst_hw_not[1],
                                         c->dst_hw_not[2], c->dst_hw_not[3],
					 c->dst_hw_not[4], c->dst_hw_not[5]);

    putchar('\n');
  }

  for(i=0; i<ip_req.index; i++) {
    c = &ip_req.c[i];
    switch(c->action) {
      case ACTION_NONE   : fputs("none\t", stdout); break;
      case ACTION_LOG    : fputs("log\t",  stdout); break;
      case ACTION_DUMP   : fputs("dump\t", stdout); break;
      case ACTION_IGNORE : fputs("ignore\t", stdout); break;
      case ACTION_DL     : fputs("dl\t", stdout); break;
      default : printf("unknown(%u) ", c->action); break;
    }
    fputs("ip\t", stdout);

    if(c->logname != NULL)
      printf("name=%s ", c->logname);
    if(c->format != NULL)
      printf("format=\"%s\" ", c->format);

    if(c->check_src_ip)
      printf("srcip=%s ", ip2string(c->src_ip));
    if(c->check_dst_ip)
      printf("dstip=%s ", ip2string(c->dst_ip));

    if(c->check_src_ip_not)
      printf("!srcip=%s ", ip2string(c->src_ip_not));
    if(c->check_dst_ip_not)
      printf("!dstip=%s ", ip2string(c->dst_ip_not));

    if(c->check_src_hw)
      printf("srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw[0], c->src_hw[1],
                                         c->src_hw[2], c->src_hw[3],
					 c->src_hw[4], c->src_hw[5]);
    if(c->check_dst_hw)
      printf("dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw[0], c->dst_hw[1],
                                         c->dst_hw[2], c->dst_hw[3],
					 c->dst_hw[4], c->dst_hw[5]);
    if(c->check_src_hw_not)
      printf("!srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw_not[0], c->src_hw_not[1],
                                         c->src_hw_not[2], c->src_hw_not[3],
					 c->src_hw_not[4], c->src_hw_not[5]);
    if(c->check_dst_hw_not)
      printf("!dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw_not[0], c->dst_hw_not[1],
                                         c->dst_hw_not[2], c->dst_hw_not[3],
					 c->dst_hw_not[4], c->dst_hw_not[5]);

    putchar('\n');
  }

  for(i=0; i<tcp_req.index; i++) {
    c = &tcp_req.c[i];
    switch(c->action) {
      case ACTION_NONE   : fputs("none\t", stdout); break;
      case ACTION_LOG    : fputs("log\t",  stdout); break;
      case ACTION_DUMP   : fputs("dump\t", stdout); break;
      case ACTION_IGNORE : fputs("ignore\t", stdout); break;
      case ACTION_DL     : fputs("dl\t", stdout); break;
      default : printf("unknown(%u) ", c->action); break;
    }
    fputs("tcp\t", stdout);

    if(c->logname != NULL)
      printf("name=%s ", c->logname);
    if(c->format != NULL)
      printf("format=\"%s\" ", c->format);

    if(c->check_src_prt) {
      if(c->src_prt1 == c->src_prt2)
        printf("srcport=%d ", c->src_prt1);
      else
        printf("srcport=%d-%d ", c->src_prt1, c->src_prt2);
    }

    if(c->check_dst_prt) {
      if(c->dst_prt1 == c->dst_prt2)
        printf("dstport=%d ", c->dst_prt1);
      else
        printf("dstport=%d-%d ", c->dst_prt1, c->dst_prt2);
    }

    if(c->check_tcp_flags_on)
      printf("flag=%d ", c->tcp_flags_on);
    if(c->check_tcp_flags_off)
      printf("!flag=%d ", c->tcp_flags_off);

    if(c->check_src_ip)
      printf("srcip=%s ", ip2string(c->src_ip));
    if(c->check_dst_ip)
      printf("dstip=%s ", ip2string(c->dst_ip));

    if(c->check_src_ip_not)
      printf("!srcip=%s ", ip2string(c->src_ip_not));
    if(c->check_dst_ip_not)
      printf("!dstip=%s ", ip2string(c->dst_ip_not));

    if(c->check_src_hw)
      printf("srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw[0], c->src_hw[1],
                                         c->src_hw[2], c->src_hw[3],
					 c->src_hw[4], c->src_hw[5]);
    if(c->check_dst_hw)
      printf("dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw[0], c->dst_hw[1],
                                         c->dst_hw[2], c->dst_hw[3],
					 c->dst_hw[4], c->dst_hw[5]);
    if(c->check_src_hw_not)
      printf("!srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw_not[0], c->src_hw_not[1],
                                         c->src_hw_not[2], c->src_hw_not[3],
					 c->src_hw_not[4], c->src_hw_not[5]);
    if(c->check_dst_hw_not)
      printf("!dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw_not[0], c->dst_hw_not[1],
                                         c->dst_hw_not[2], c->dst_hw_not[3],
					 c->dst_hw_not[4], c->dst_hw_not[5]);

    putchar('\n');
  }

  for(i=0; i<udp_req.index; i++) {
    c = &udp_req.c[i];
    switch(c->action) {
      case ACTION_NONE   : fputs("none\t", stdout); break;
      case ACTION_LOG    : fputs("log\t",  stdout); break;
      case ACTION_DUMP   : fputs("dump\t", stdout); break;
      case ACTION_IGNORE : fputs("ignore\t", stdout); break;
      case ACTION_DL     : fputs("dl\t", stdout); break;
      default : printf("unknown(%u) ", c->action); break;
    }
    fputs("udp\t", stdout);

    if(c->logname != NULL)
      printf("name=%s ", c->logname);
    if(c->format != NULL)
      printf("format=\"%s\" ", c->format);

    if(c->check_src_prt) {
      if(c->src_prt1 == c->src_prt2) 
        printf("srcport=%d ", c->src_prt1);
      else
        printf("srcport=%d-%d ", c->src_prt1, c->src_prt2); 
    }

    if(c->check_dst_prt) {
      if(c->dst_prt1 == c->dst_prt2) 
        printf("dstport=%d ", c->dst_prt1);
      else
        printf("dstport=%d-%d ", c->dst_prt1, c->dst_prt2);
    }

    if(c->check_src_ip)
      printf("srcip=%s ", ip2string(c->src_ip));
    if(c->check_dst_ip)
      printf("dstip=%s ", ip2string(c->dst_ip));

    if(c->check_src_ip_not)
      printf("!srcip=%s ", ip2string(c->src_ip_not));
    if(c->check_dst_ip_not)
      printf("!dstip=%s ", ip2string(c->dst_ip_not));

    if(c->check_src_hw)
      printf("srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw[0], c->src_hw[1],
                                         c->src_hw[2], c->src_hw[3],
					 c->src_hw[4], c->src_hw[5]);
    if(c->check_dst_hw)
      printf("dsthw=%02x:%02x:%02x:%02x:%02x:%02x ",
					 c->dst_hw[0], c->dst_hw[1],
                                         c->dst_hw[2], c->dst_hw[3],
					 c->dst_hw[4], c->dst_hw[5]);
    if(c->check_src_hw_not)
      printf("!srchw=%02x:%02x:%02x:%02x:%02x:%02x ",
					 c->src_hw_not[0], c->src_hw_not[1],
                                         c->src_hw_not[2], c->src_hw_not[3],
					 c->src_hw_not[4], c->src_hw_not[5]);
    if(c->check_dst_hw_not)
      printf("!dsthw=%02x:%02x:%02x:%02x:%02x:%02x ",
					 c->dst_hw_not[0], c->dst_hw_not[1],
                                         c->dst_hw_not[2], c->dst_hw_not[3],
					 c->dst_hw_not[4], c->dst_hw_not[5]);

    putchar('\n');
  }

  for(i=0; i<raw_req.index; i++) {
    c = &raw_req.c[i];
    switch(c->action) {
      case ACTION_NONE   : fputs("none\t", stdout); break;
      case ACTION_LOG    : fputs("log\t",  stdout); break;
      case ACTION_DUMP   : fputs("dump\t", stdout); break;
      case ACTION_IGNORE : fputs("ignore\t", stdout); break;
      case ACTION_DL     : fputs("dl\t", stdout); break;
      default : printf("unknown(%u) ", c->action); break;
    }
    fputs("raw\t", stdout);

    if(c->logname != NULL)
      printf("name=%s ", c->logname);
    if(c->format != NULL)
      printf("format=\"%s\" ", c->format);

    if(c->check_src_hw)
      printf("srchw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->src_hw[0], c->src_hw[1],
                                         c->src_hw[2], c->src_hw[3],
					 c->src_hw[4], c->src_hw[5]);
    if(c->check_dst_hw)
      printf("dsthw=%02x:%02x:%02x:%02x:%02x:%02x ", 
					 c->dst_hw[0], c->dst_hw[1],
                                         c->dst_hw[2], c->dst_hw[3],
					 c->dst_hw[4], c->dst_hw[5]);
    if(c->check_src_hw_not)
      printf("!srchw=%02x:%02x:%02x:%02x:%02x:%02x ",
					 c->src_hw_not[0], c->src_hw_not[1],
                                         c->src_hw_not[2], c->src_hw_not[3],
					 c->src_hw_not[4], c->src_hw_not[5]);
    if(c->check_dst_hw_not)
      printf("!dsthw=%02x:%02x:%02x:%02x:%02x:%02x ",
					 c->dst_hw_not[0], c->dst_hw_not[1],
                                         c->dst_hw_not[2], c->dst_hw_not[3],
					 c->dst_hw_not[4], c->dst_hw_not[5]);

    putchar('\n');
  }
}
