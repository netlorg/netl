/*==============================================================================
| lookup.h - lookup tables for ICMP types and CODEs
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef LOOKUP_H
#define LOOKUP_H

struct lookupitem {
  int	index;
  char	*name;
};

#define MAXICMPTYPE		13
#define MAXICMPCODE		22

extern struct lookupitem icmptype[MAXICMPTYPE];
extern struct lookupitem icmpcode[MAXICMPCODE];

#endif /* LOOKUP_H */
