/*==============================================================================
| config.c
|   read config file for netl
|
| this code is (c) 1997 Graham THE Ollis
|
|   your free to modify and distribute this program as long as this header is
|   retained, source code is made *freely* available and you document your 
|   changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  23 Feb 97  G. Ollis	created module
|  25 Feb 97  G. Ollis	.91 added port range support
|=============================================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "global.h"
#include "ether.h"

#include "config.h"
#include "resolve.h"
#include "lookup.h"

/*==============================================================================
| globals
==============================================================================*/

static int line=0;
struct configlist icmp_req, tcp_req, udp_req;
int configmax = 0;
char *emptystring = "";
char netdevice[255] = "eth0";

/*==============================================================================
| copyname
==============================================================================*/

static char *
copyname(char *s) 
{
  char *tmp = (char *) malloc(strlen(s) + 1);
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
    return net16(service->s_port);
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

        /*======================================================================
        | this swap is a bit of a haxor as we say in the old school
	| if the compiler is smart, this will be really fast.
        ======================================================================*/

        if(*num2 < *num1) { 
          *num2 ^= *num1;
	  *num1 ^= *num2;
	  *num2 ^= *num1;
        }
        return TRUE;
      }
      fprintf(stderr, "%s: warning unknown port range %s-%s (line %d)\n",
              prog, name1, name2, line);
      return FALSE;
    }
  }

  if((*num1 = getportnum(name1, prot)) !=0) {
    if(num2 != NULL)
      *num2 = *num1;
    return TRUE;
  }

  fprintf(stderr, "%s: warning: unknown port %s (line %d)\n",
          prog, name1, line);
  return FALSE;
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

  if((buff = malloc(strlen(name) + 1))==NULL) {
    fprintf(stderr, "%s: could not malloc()\n", prog);
    exit(2);
  }
  strcpy(buff, name);

  element = strtok(buff, ".");
  while(i < 4) {
    if(element == NULL) {
      fprintf(stderr, "%s: warning: could not parse ip %s (line %d)\n",
              prog, name, line);
      return FALSE;
    }
    tmp[i++] = atoi(element);
    element = strtok(NULL, ".");
  }

  return TRUE;
}

/*==============================================================================
| icmp
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

  fprintf(stderr, "%s: warning: unknown icmp %s (line %d)\n",
          prog, name, line);

  return FALSE;
}

/*==============================================================================
| TCP flags
==============================================================================*/

static int
modifyflags(struct flagbyte *fb, u8 other, char *name)
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
      fprintf(stderr, "%s: warning: unknown tcp flag %s (line %d)\n",
		prog, tmp, line);

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
  if( (l->c=(struct configitem *) malloc(sizeof(struct configitem)*100))==NULL) {
    fprintf(stderr, "%s: error, unable to malloc\n", prog);
    exit(2);
  }
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

  tmp=(struct configitem *) malloc(memorysize);
  if(tmp==NULL) {
    fprintf(stderr, "%s: error, unable to malloc\n", prog);
    exit(2);
  }

  memcpy(tmp, l->c, memorysize);
  free(l->c);
  l->c = tmp;
  l->size = size;
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


    /* tokenize the config line */
    tokens[0] = strtok(buff, "\t\n ");
    i = 0;
    while(tokens[i] != NULL) 
      tokens[++i] = strtok(NULL, "\t\n ");

    /* blank line, go to the next one */
    if(tokens[0] == NULL)
      return;

    if(!strcmp(tokens[0], "device")) {
      if(tokens[1] == NULL) 
        return;
      strncpy(netdevice, tokens[1], 255);
      return;
    }

    if(i < 3) {
      fprintf(stderr, "%s: warning: bad config line %d\n", prog, line);
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
    ==========================================================================*/

    if(!strcmp(tokens[0], "log"))
      citem.action = ACTION_LOG;
    else if(!strcmp(tokens[0], "dump"))
      citem.action = ACTION_DUMP;
    else if(!strcmp(tokens[0], "ignore"))
      citem.action = ACTION_IGNORE;
    else {
      fprintf(stderr, "%s: warning: unknown action %s (line %d)\n", 
              prog, tokens[0], line);
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
    else {
      fprintf(stderr, "%s: warning: unknown protocol %s (line %d)\n", 
              prog, tokens[1], line);
      return;
    }

    /*==========================================================================
    | any remaining fields are restriction fields
    |
    | name=		syslog name
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
    | type=		icmp type
    | code=		icmp code
    ==========================================================================*/

    citem.logname = emptystring;

    for(n=2; n<i; n++) {

      /*========================================================================
      | name=
      ========================================================================*/

      if(!strncmp(tokens[n], "name=", 5)) {
        citem.logname = copyname(tokens[n] + 5);
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
		(struct flagbyte *) &citem.tcp_flags_on, 
		citem.tcp_flags_off,
		tokens[n] + 5);
      } 
      else if(!strncmp(tokens[n], "!flag=", 6)) {
        citem.check_tcp_flags_off = modifyflags(
		(struct flagbyte *) &citem.tcp_flags_off, 
		citem.tcp_flags_on,
		tokens[n] + 6);
      } 

      /*========================================================================
      | unknown
      ========================================================================*/

      else {
        fprintf(stderr, "%s: warning: unknown requirement %s (line %d)\n",
                prog, tokens[n], line);        
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
}

void
postconfig()
{
  resizelist(&icmp_req, icmp_req.index);
  resizelist(&tcp_req, tcp_req.index);
  resizelist(&udp_req, udp_req.index);
}

/*==============================================================================
| readconfig(char *prog)
|
|  this function reads the config file and alters the config structure
|  apropriately
==============================================================================*/

void
readconfig(char *confname)
{
  FILE		*fp;
  char		buff[NETL_CONFIG_MAXWIDTH];
  int		i;

  if((fp=fopen(confname, "r")) == NULL) {
    fprintf(stderr, "%s: error opening %s for read\n", prog, confname);
    exit(2);
  }

  setservent(TRUE);

  while(fgets(buff, NETL_CONFIG_MAXWIDTH, fp) != NULL) {
    line++;

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

  endservent();
}
