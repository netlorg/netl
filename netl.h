/*==============================================================================
| netl - log EVERYTHING possible
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef NETL_H
#define NETL_H

#define COPYVER "0.92 (c) 1997 Graham THE Ollis <ollisg@ns.arizona.edu>"

/*==============================================================================
| which "facility" should we send the syslog logs to?
==============================================================================*/

#define NETL_LOG_FACILITY	LOG_LOCAL4

/*==============================================================================
| prototypes
==============================================================================*/

int	netl(char *dev);
void	dgdump(u8 *dg, char *name, int len);
void	checkicmp(u8 *dg, struct iphdr ip, struct icmphdr *h, int len);
void	checktcp(u8 *dg, struct iphdr ip, struct tcphdr *h, int len);
void	checkudp(u8 *dg, struct iphdr ip, struct udphdr *h, int len);
void	parsedg(u8 *dg, int len);

#endif /* NETL_H */
