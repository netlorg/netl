/*==============================================================================
| resolve.h - ip => hostname resolution and cacheing functions
| 
| coded and tested under linux 2.0.23, 2.0.26, stealth kernel 2.0.29
|  by graham the ollis <ollisg@ns.arizona.edu>
|
| your free to modify and distribute this program as long as this header is
| retained, source code is made *freely* available and you document your 
| changes in some readable manner.
==============================================================================*/

#ifndef RESOLVE_H
#define RESOLVE_H

/*==============================================================================
| prototypes
==============================================================================*/

char	*addip(const char *s, u32 ip);
char	*ip2string(u32 ip);
char	*search(u32 ip);
u32	searchbyname(char *);
void	clearipcache();

#endif /* RESOLVE_H */
