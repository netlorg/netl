#ifndef _INCLUDES_H
#define _INCLUDES_H

#include <sys/types.h>
#ifdef _linux_
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#endif
#include <sys/param.h>
/* #include <sys/queue.h> */
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifndef linux
#include <netinet/ip_var.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
/* #include <err.h> */
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/if_ether.h>
#ifdef _linux_
#include "linux_flood_net.h"
#else
#include <netinet/tcp.h>
#endif
#include <netinet/udp.h>

#include <sys/stat.h>
#include <fcntl.h>
#ifndef linux
#include <sys/sockio.h>
#endif
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef SOLARIS
#include <net/if_arp.h>
#include <sys/stropts.h>
#include <sys/dlpi.h>
#endif

#include <signal.h>
#include <sys/mman.h>

#ifdef _OpenBSD_
#include <sys/mbuf.h>
#include <sys/timeb.h>
#if BSD < 199103
#include <sys/fcntlcom.h>
#endif
#ifdef XXX
#include <sys/dir.h>
#endif
#include <sys/dirent.h>
#include <net/bpf.h>
#include <kvm.h>
#include <netinet/in_var.h>
#include <net/if_dl.h>
#endif

#include <arpa/nameser.h>

#include "ip_icmp.h"


#endif /* _INCLUDES_H */
