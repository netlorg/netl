/*==============================================================================
| netl
|   optimized (and debugged) by Graham THE Ollis <ollisg@ns.arizona.edu>
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
|  01 Feb 97  G. Ollis	modified, commented (and debugged)
|  08 Feb 97  G. Ollis	added IP address resolving.
|  23 Feb 97  G. Ollis	combined all network monitoring in to single program
|=============================================================================*/

char	*id = "@(#)netl by graham the ollis <ollisg@ns.arizona.edu>";

#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>

#include "netl.h"
#include "sighandle.h"

/*==============================================================================
| Globals
|=============================================================================*/

struct ifreq oldifr, ifr;
u32 dumpindex = 0;

/*==============================================================================
| int main(int, char **)
|=============================================================================*/

int
main(int argc, char *argv[])
{
  pid_t		temp;

  if(getuid() != 0) {
    fprintf(stderr, "%s: must be run as root\n", argv[0]);
    return 1;
  }

  if(argc > 2) {
    fprintf(stderr, "usage: %s [conf-file]\n", argv[0]);
    return 1;
  }
  if(argc == 2) 
    readconfig(argv[0], argv[1]);
  else
    readconfig(argv[0], NETL_CONFIG);

  puts("netl 0.9 by graham the ollis <ollisg@ns.arizona.edu>");

  if((temp = fork()) == 0) 
    return netl(netdevice);

  if(temp == -1) {
    fprintf(stderr, "%s: unable to fork\n", argv[0]);
    return 1;
  }

  return 0;
}

/*==============================================================================
| void netl(char *)
|=============================================================================*/

int
netl(char *dev) {
  int		l;
  int		sock, length;
  struct	sockaddr_in name;
  unsigned char buf[4096];
  unsigned int	fromlen;

  openlog("netl", 0, NETL_LOG_FACILITY);
  syslog(LOG_INFO, "starting netl, logging %s", dev);
  handle();

  /*============================================================================
  | Get a socket which will collect all packets
  |===========================================================================*/
  sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));

  if (sock < 0) {
    syslog(LOG_ERR, "cannot open raw socket, die\n", stderr);
    return 1;
  }

  /*============================================================================
  | Configure ethernet device
  |===========================================================================*/

  strcpy(ifr.ifr_name, dev);
  strcpy(oldifr.ifr_name, dev);

  /*============================================================================
  | Get flags and place them in ifr structure
  |===========================================================================*/

  if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    syslog(LOG_ERR, "unable to get %s flags, die", dev);
    return 1;
  }

  /*============================================================================
  | Get flags and place them in oldifr structure
  | This will be used later to change ether device characteristics back
  | to their original value
  |===========================================================================*/

  if(ioctl(sock, SIOCGIFFLAGS, &oldifr) < 0) {
    syslog(LOG_ERR, "unable to get %s flags, die\n", dev);
    return 1;
  }

  /*============================================================================
  | Set the promiscous flag
  |===========================================================================*/

  ifr.ifr_flags |= IFF_PROMISC;

  /*============================================================================
  | Set the device flags
  |===========================================================================*/

  if(ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    syslog(LOG_ERR, "Unable to set %s flags, die", dev);
    return 1;
  } 

  /*============================================================================
  | Set up sockaddr
  |===========================================================================*/

  name.sin_family = AF_INET;
  name.sin_addr.s_addr = INADDR_ANY;
  name.sin_port = 0;

  length = sizeof(name);

  if (getsockname(sock, (struct sockaddr *) &name, &length) < 0) {
    syslog(LOG_ERR, "Error: Can't get socket name, die");
    return 1;
  }

  /*============================================================================
  | Entering the data collection loop
  |===========================================================================*/

  for(;;) {
    if((l = recvfrom(sock, buf, 1024, 0, 
                     (struct sockaddr *)&name, &fromlen)) < 0)
      syslog(LOG_ERR, "Error receiving RAW packet\n");
    else 
      parsedg(buf, l);
  }

  return 0;
}

/*==============================================================================
| dump ip datagram
|=============================================================================*/

void dgdump(u8 *dg, char *name, int len)
{
  char		fn[1024];
  FILE		*fp;

  sprintf(fn, "/tmp/netl/%s-%d-%d", name, getpid(), dumpindex++);
  if((fp=fopen(fn, "w"))==NULL) {
    syslog(LOG_ERR, "unable to open dump file %s", fn);
    return;
  }
  if(fwrite(dg, 1, len, fp) != len)
    syslog(LOG_ERR, "error writing to dump file %s", fn);
  fclose(fp);
}

/*==============================================================================
| check/log icmp
|=============================================================================*/

void
checkicmp(u8 *dg, struct iphdr ip, struct icmphdr *h, int len)
{
  int i;
  int logged=FALSE,dumped=FALSE;

  for(i=0; i<configmax; i++) {

    if(
       /* if we already logged or dumped it, we may not have to check it */
       (config[i].action == ACTION_LOG && logged) ||
       (config[i].action == ACTION_DUMP && dumped) ||

       /* must be ICMP */
       (config[i].protocol != PROTOCOL_ICMP) ||

       /* must be the correct type */
       (config[i].check_icmp_type && config[i].icmp_type != h->type) ||

       /* addresses must be correct */
       (config[i].check_src_ip && config[i].src_ip != ip.saddr) ||
       (config[i].check_dst_ip && config[i].dst_ip != ip.daddr) ||
       (config[i].check_src_ip_not && config[i].src_ip_not == ip.saddr) ||
       (config[i].check_dst_ip_not && config[i].dst_ip_not == ip.daddr) 
      )
      continue;

    switch(config[i].action) {
      case ACTION_LOG:
        syslog(LOG_NOTICE,
		"%s %s => %s\n",
                config[i].logname,
                ip2string(ip.saddr),
                ip2string(ip.daddr));
        logged = TRUE;
        break;

      default:
        dgdump(dg, config[i].logname, len);
        dumped = TRUE;
        break;
    }

  }
}

/*==============================================================================
| check/log tcp
|=============================================================================*/

void
checktcp(u8 *dg, struct iphdr ip, struct tcphdr *h, int len)
{
  int i;
  int logged=FALSE,dumped=FALSE;
  u8 flags=*(((char *) h) + 13);

  for(i=0; i<configmax; i++) {

    if(
       /* if we already logged or dumped it, we may not have to check it */
       (config[i].action == ACTION_LOG && logged) ||
       (config[i].action == ACTION_DUMP && dumped) ||

       /* must be TCP */
       (config[i].protocol != PROTOCOL_TCP) ||

       /* port must be correct */
       (config[i].check_src_prt && config[i].src_prt != h->source) ||
       (config[i].check_dst_prt && config[i].dst_prt != h->dest) ||

       /* flags must be correct */
       (config[i].check_tcp_flags_on && 
           (flags & config[i].tcp_flags_on) != config[i].tcp_flags_on) ||
       (config[i].check_tcp_flags_off && 
           (~flags & config[i].tcp_flags_off) != config[i].tcp_flags_off) ||

       /* addresses must be correct */
       (config[i].check_src_ip && config[i].src_ip != ip.saddr) ||
       (config[i].check_dst_ip && config[i].dst_ip != ip.daddr) ||
       (config[i].check_src_ip_not && config[i].src_ip_not == ip.saddr) ||
       (config[i].check_dst_ip_not && config[i].dst_ip_not == ip.daddr) 
      )
      continue;

    switch(config[i].action) {
      case ACTION_LOG:
        syslog(LOG_NOTICE,
		"%s %s:%d => %s:%d\n",
                config[i].logname,
                ip2string(ip.saddr),
		net16(h->source),
                ip2string(ip.daddr),
                net16(h->dest));
        logged = TRUE;
        break;

      default:
        dgdump(dg, config[i].logname, len);
        dumped = TRUE;
        break;
    }

  }
}

/*==============================================================================
| check/log udp
|=============================================================================*/

void
checkudp(u8 *dg, struct iphdr ip, struct udphdr *h, int len)
{
  int i;
  int logged=FALSE,dumped=FALSE;

  for(i=0; i<configmax; i++) {

    if(
       /* if we already logged or dumped it, we may not have to check it */
       (config[i].action == ACTION_LOG && logged) ||
       (config[i].action == ACTION_DUMP && dumped) ||

       /* must be TCP */
       (config[i].protocol != PROTOCOL_UDP) ||

       /* port must be correct */
       (config[i].check_src_prt && config[i].src_prt != h->source) ||
       (config[i].check_dst_prt && config[i].dst_prt != h->dest) ||

       /* addresses must be correct */
       (config[i].check_src_ip && config[i].src_ip != ip.saddr) ||
       (config[i].check_dst_ip && config[i].dst_ip != ip.daddr) ||
       (config[i].check_src_ip_not && config[i].src_ip_not == ip.saddr) ||
       (config[i].check_dst_ip_not && config[i].dst_ip_not == ip.daddr) 
      )
      continue;

    switch(config[i].action) {
      case ACTION_LOG:
        syslog(LOG_NOTICE,
		"%s %s:%d => %s:%d\n",
                config[i].logname,
                ip2string(ip.saddr),
		net16(h->source),
                ip2string(ip.daddr),
                net16(h->dest));
        logged = TRUE;
        break;

      default:
        dgdump(dg, config[i].logname, len);
        dumped = TRUE;
        break;
    }

  }
}

/*==============================================================================
| void parsedg(u8 *buff);
|=============================================================================*/

void
parsedg(u8 *dg, int len)
{
  struct machdr		*mac = (struct machdr*) dg;
  struct iphdr		*ip = (struct iphdr*) &dg[14];

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

    case PROTOCOL_ICMP:
      checkicmp(dg, 
          *ip,
          (struct icmphdr *) &dg[sizeof(struct machdr) + (ip->ihl << 2)],
          len);
      break;

    case PROTOCOL_TCP:
      checktcp(dg,
          *ip,
          (struct tcphdr *) &dg[sizeof(struct machdr) + (ip->ihl << 2)],
          len);
      break;

    case PROTOCOL_UDP:
      checkudp(dg,
          *ip,
          (struct udphdr *) &dg[sizeof(struct machdr) + (ip->ihl << 2)],
          len);
      break;

    default:
      /* I don't know this subprotocol */
      break;
  }

}

