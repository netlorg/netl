/*==============================================================================
| config.c
|   read config file for netl
|
| this code is (c) 1997 Graham THE Ollis
|
|   this program is now written like it should be.
|   your free to modify and distribute this program as long as this header is
|   retained, source code is made *freely* available and you document your 
|   changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  23 Feb 97  G. Ollis	created module
|=============================================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include "netl.h"

/*==============================================================================
| globals
==============================================================================*/

static int line=0;
static char *prog = NULL;
struct configitem *config = NULL;
int configmax = 0;
char *emptystring = "";
char netdevice[255] = "eth0";

/*==============================================================================
| lookup tables
==============================================================================*/

struct lookupitem {
  int	index;
  char	*name;
};

#define MAXICMPTYPE		13
static struct lookupitem icmptype[MAXICMPTYPE] = 
			      { {ICMP_ECHOREPLY,	"echoreply"},
				{ICMP_DEST_UNREACH,	"dest_unreach"},
				{ICMP_SOURCE_QUENCH,	"source_quench"},
				{ICMP_REDIRECT,		"redirect"},
				{ICMP_ECHO,		"echo"},
				{ICMP_TIME_EXCEEDED,	"time_exceeded"},
				{ICMP_PARAMETERPROB,	"parameterprob"},
				{ICMP_TIMESTAMP,	"timestamp"},
				{ICMP_TIMESTAMPREPLY,	"timestampreply"},
				{ICMP_INFO_REQUEST,	"info_request"},
				{ICMP_INFO_REPLY,	"info_reply"},
				{ICMP_ADDRESS,		"address"},
				{ICMP_ADDRESSREPLY,	"addressreply"}
			      };

#define MAXICMPCODE		22
static struct lookupitem icmpcode[MAXICMPCODE] =
			      { {ICMP_NET_UNREACH,	"net_unreach"},
				{ICMP_HOST_UNREACH,	"host_unreach"},
				{ICMP_PROT_UNREACH,	"prot_unreach"},
				{ICMP_PORT_UNREACH,	"port_unreach"},
				{ICMP_FRAG_NEEDED,	"frag_needed"},
				{ICMP_SR_FAILED,	"sr_failed"},
				{ICMP_NET_UNKNOWN,	"net_unknown"},
				{ICMP_HOST_UNKNOWN,	"host_unknown"},
				{ICMP_HOST_ISOLATED,	"host_isolated"},
				{ICMP_NET_ANO,		"net_ano"},
				{ICMP_HOST_ANO,		"host_ano"},
				{ICMP_NET_UNR_TOS,	"net_unr_tos"},
				{ICMP_HOST_UNR_TOS,	"host_unr_tos"},
				{ICMP_PKT_FILTERED,	"pkt_filtered"},
				{ICMP_PREC_VIOLATION,	"prec_violation"},
				{ICMP_PREC_CUTOFF,	"prec_cutoff"},
				{ICMP_REDIR_NET,	"redir_net"},
				{ICMP_REDIR_HOST,	"redir_host"},
				{ICMP_REDIR_NETTOS,	"redir_nettos"},
				{ICMP_REDIR_HOSTTOS,	"redir_hosttos"},
				{ICMP_EXC_TTL,		"exc_ttl"},
				{ICMP_EXC_FRAGTIME,	"_exc_fragtime"}
			      };

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
  int		i;
  struct servent	*service;

  i=atoi(s);
  if(i != 0)
    return native16(i);

  if(prot == PROTOCOL_TCP) 
    service = getservbyname(s, "tcp");
  else if(prot == PROTOCOL_UDP)
    service = getservbyname(s, "udp");
  else
    return 0;

  if(service == NULL)
    return 0;
  else
    return service->s_port;
}

/*==============================================================================
| port
==============================================================================*/

static int
modifyport(u16 *num, char *name, u8 prot)
{
  if((*num = getportnum(name, prot)) !=0)
    return TRUE;

  fprintf(stderr, "%s: warning: unknown port %s (line %d)\n",
          prog, name, line);
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
| readconfig(char *prog)
|
|  this function reads the config file and alters the config structure
|  apropriately
==============================================================================*/

void
readconfig(char *programname, char *confname)
{
  FILE		*fp;
  char		buff[NETL_CONFIG_MAXWIDTH];
  char		*tokens[NETL_CONFIG_MAXTOKENS];
  int		i,n;
  u32		tmp;

  prog = programname;

  if((config = malloc(sizeof(struct configitem) * NETL_CONFIG_MAXREQ)) == NULL) {
    fprintf(stderr, "%s: unable to malloc()\n", prog);
    exit(2);
  }

  if((fp=fopen(confname, "r")) == NULL) {
    fprintf(stderr, "%s: error opening %s for read\n", prog, NETL_CONFIG);
    exit(2);
  }

  setservent(TRUE);

  while(fgets(buff, NETL_CONFIG_MAXWIDTH, fp) != NULL) {
    line++;

    /* skip comment lines */
    if(buff[0] == '#') 
      continue;

    /* tokenize the config line */
    tokens[0] = strtok(buff, "\t\n ");
    i = 0;
    while(tokens[i] != NULL) 
      tokens[++i] = strtok(NULL, "\t\n ");

    /* blank line, go to the next one */
    if(tokens[0] == NULL)
      continue;

    if(!strcmp(tokens[0], "device")) {
      if(tokens[1] == NULL) 
        continue;
      strncpy(netdevice, tokens[1], 255);
      continue;
    }

    if(i < 3) {
      fprintf(stderr, "%s: warning: bad config line %d\n", prog, line);
      continue;
    }

    if(!strcmp(tokens[0], "alias")) {
      modifyip(&tmp, tokens[2]);
      addip(tokens[1], tmp);
      continue;
    }

    memset(&config[configmax], 0, sizeof(struct configitem));

    /*==========================================================================
    | check the action field.  this should be one of:
    |  * log the given item should be logged using syslog
    |  * dump the given item should be dumped to a file in /tmp/netl/
    ==========================================================================*/

    if(!strcmp(tokens[0], "log"))
      config[configmax].action = ACTION_LOG;
    else if(!strcmp(tokens[0], "dump"))
      config[configmax].action = ACTION_DUMP;
    else {
      fprintf(stderr, "%s: warning: unknown action %s (line %d)\n", 
              prog, tokens[0], line);
      continue;
    }

    /*==========================================================================
    | next field is the protocol field.  this should be one of:
    |  * tcp
    |  * udp
    |  * icmp
    ==========================================================================*/

    if(!strcmp(tokens[1], "tcp")) 
      config[configmax].protocol = PROTOCOL_TCP;
    else if(!strcmp(tokens[1], "icmp"))
      config[configmax].protocol = PROTOCOL_ICMP;
    else if(!strcmp(tokens[1], "udp")) 
      config[configmax].protocol = PROTOCOL_UDP;
    else {
      fprintf(stderr, "%s: warning: unknown protocol %s (line %d)\n", 
              prog, tokens[1], line);
      continue;
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

    config[configmax].logname = emptystring;

    for(n=2; n<i; n++) {

      /*========================================================================
      | name=
      ========================================================================*/

      if(!strncmp(tokens[n], "name=", 5)) {
        config[configmax].logname = copyname(tokens[n] + 5);
      }

      /*========================================================================
      | ports
      ========================================================================*/
      
      else if(!strncmp(tokens[n], "dstport=", 8)) {
        config[configmax].check_dst_prt = modifyport(
               &config[configmax].dst_prt,
               tokens[n] + 8,
               config[configmax].protocol);
      }
      else if(!strncmp(tokens[n], "!dstport=", 9)) {
        config[configmax].check_dst_prt_not = modifyport(
               &config[configmax].dst_prt_not,
               tokens[n] + 9,
               config[configmax].protocol);
      }
      else if(!strncmp(tokens[n], "srcport=", 8)) {
        config[configmax].check_src_prt = modifyport(
               &config[configmax].src_prt,
               tokens[n] + 8,
               config[configmax].protocol);
      }
      else if(!strncmp(tokens[n], "!srcport=", 9)) {
        config[configmax].check_src_prt_not = modifyport(
               &config[configmax].src_prt_not,
               tokens[n] + 9,
               config[configmax].protocol);
      }

      /*========================================================================
      | IP addresses
      ========================================================================*/

      else if(!strncmp(tokens[n], "dstip=", 6)) {
        config[configmax].check_dst_ip = modifyip(
               &config[configmax].dst_ip,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!dstip=", 7)) {
        config[configmax].check_dst_ip_not = modifyip(
               &config[configmax].dst_ip_not,
               tokens[n] + 7);
      }

      else if(!strncmp(tokens[n], "srcip=", 6)) {
        config[configmax].check_src_ip = modifyip(
               &config[configmax].src_ip,
               tokens[n] + 6);
      }
      else if(!strncmp(tokens[n], "!srcip=", 7)) {
        config[configmax].check_src_ip_not = modifyip(
               &config[configmax].src_ip_not,
               tokens[n] + 7);
      }

      /*========================================================================
      | ICMP stuff
      ========================================================================*/

      else if(!strncmp(tokens[n], "type=", 5)) {
        config[configmax].check_icmp_type = modifyicmp(
		&config[configmax].icmp_type,
		tokens[n] + 5,
		icmptype,
		MAXICMPTYPE);
      }
      else if(!strncmp(tokens[n], "code=", 5)) {
        config[configmax].check_icmp_type = modifyicmp(
		&config[configmax].icmp_type,
		tokens[n] + 5,
		icmpcode,
		MAXICMPCODE);
      }

      /*========================================================================
      | TCP flags
      ========================================================================*/

      else if(!strncmp(tokens[n], "flag=", 5)) {
        config[configmax].check_tcp_flags_on = modifyflags(
		(struct flagbyte *) &config[configmax].tcp_flags_on, 
		config[configmax].tcp_flags_off,
		tokens[n] + 5);
      } 
      else if(!strncmp(tokens[n], "!flag=", 6)) {
        config[configmax].check_tcp_flags_off = modifyflags(
		(struct flagbyte *) &config[configmax].tcp_flags_off, 
		config[configmax].tcp_flags_on,
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

    configmax++;
    if(configmax > NETL_CONFIG_MAXREQ) {
      fprintf(stderr, "%s: warning: too many requirements in config file (line %d)\n",
             prog, line);
      fprintf(stderr, "%s: modify source code to increase max requirements\n",prog);
      break;
    }
  }
  endservent();

}
