/*==============================================================================
| resolve.c
|   do host name look ups in something of an efficent manner
|
| (c) 1997 Graham THE Ollis
|
|  Date       Name	Revision
|  ---------  --------  --------
|  08 Feb 97  G. Ollis	created
|  23 Feb 97  G. Ollis	account for the possible failure of a hostname lookup.
|			use 32 bit unsigned integers instead of 4 bytes char
|			arrays like i should have done in the first place.
|=============================================================================*/

#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "netl.h"

struct listtype {
  u32 ip;				/* ip number: x.x.x.x		*/
  struct listtype *next;		/* next node			*/
  char *name;				/* hostname			*/
};

static struct listtype *cache = NULL;

char *search(u32 ip);

/*==============================================================================
| addip();
| add an ip/hostname to the search stack.  this is handy for local aliases.
|=============================================================================*/

char *
addip(const char *s, u32 ip)
{
  struct listtype	*tmp;
  int			len;

  tmp = (struct listtype *) malloc(sizeof(struct listtype));
  tmp->name = (char *) malloc((len = strlen(s) + 1));
  memcpy(tmp->name, s, len);
  tmp->ip = ip;
  tmp->next = cache;
  cache = tmp;

  return tmp->name;
}

/*==============================================================================
| ip2string();
| convert an ip number and return a pointer to an internal string.  the
| name has been cached so next look up should be marginally faster.
|=============================================================================*/

char *
ip2string(u32 ip)
{
  char			buff[20];
  struct hostent *	herhost;
  u8 			*tmp;

  if((tmp=search(ip)) != NULL)
    return tmp;

  tmp = (char *) &ip;
  sprintf(buff, "%d.%d.%d.%d", tmp[0], tmp[1], tmp[2], tmp[3]);
  if(
     ((herhost = gethostbyname(buff)) != NULL) &&
     ((herhost = gethostbyaddr(herhost->h_addr_list[0], 
                          herhost->h_length,
			  herhost->h_addrtype)) != NULL)
    ) {
    tmp = addip(herhost->h_name, ip);
  } else {
    tmp = addip(buff, ip);
  }

  return tmp;
}

/*==============================================================================
| search();
| convert an ip number and return a pointer to an internal string.  the
| name has been cached so next look up should be marginally faster.
|=============================================================================*/

char *
search(u32 ip) 
{
  struct listtype *tmp;

  for(tmp = cache; tmp != NULL; tmp = tmp->next) {
    if(ip == tmp->ip) {
      return tmp->name;
    }
  }
  return NULL;
}

/*==============================================================================
| searchbyname();
|=============================================================================*/

u32
searchbyname(char *name) 
{
  struct listtype *tmp;

  for(tmp = cache; tmp != NULL; tmp = tmp->next) {
    if(!strcmp(name, tmp->name)) {
      return tmp->ip;
    }
  }
  return 0;
}

/*==============================================================================
| clearcache();
| clear the internal cache for this module.
|=============================================================================*/

void
clearipcache()
{
  struct listtype *tmp;

  for(tmp=cache; tmp != NULL; tmp = tmp->next) {
    free(tmp);
  }
  cache = NULL;
}
