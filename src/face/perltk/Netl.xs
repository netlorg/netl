#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "netl/global.h"
#include "netl/resolve.h"
#include "netl/options.h"
#include "netl/ether.h"
#include "netl/ip.h"
#include "netl/filter.h"
#include "netl/action.h"
#include "netl/config.h"
#include "netl/catch.h"

extern char *netl_config_y_2str(struct configitem *c);
extern char *configfile;

extern int netl_nmopen_pretend;

static double
constant(char *name, int arg)
{
    errno = 0;
    switch (*name) {
    case 'A':
	break;
    case 'B':
	break;
    case 'C':
	break;
    case 'D':
	break;
    case 'E':
	break;
    case 'F':
	break;
    case 'G':
	break;
    case 'H':
	break;
    case 'I':
	break;
    case 'J':
	break;
    case 'K':
	break;
    case 'L':
	break;
    case 'M':
	break;
    case 'N':
	if (strEQ(name, "NETL_VER_MAJOR"))
#ifdef NETL_VER_MAJOR
	    return NETL_VER_MAJOR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NETL_VER_MINOR"))
#ifdef NETL_VER_MINOR
	    return NETL_VER_MINOR;
#else
	    goto not_there;
#endif
	break;
    case 'O':
	break;
    case 'P':
	break;
    case 'Q':
	break;
    case 'R':
	break;
    case 'S':
	break;
    case 'T':
	break;
    case 'U':
	break;
    case 'V':
	break;
    case 'W':
	break;
    case 'X':
	break;
    case 'Y':
	break;
    case 'Z':
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = Netl			PACKAGE = Netl


double
constant(name,arg)
	char *		name
	int		arg


int
_netl(dev)
	char *		dev
	CODE:
		RETVAL = netl(dev);
	OUTPUT:
	RETVAL


void
_set_prog(s)
	char *s
	CODE:
		netl_guts_prog = s;



void
parsecmdline(...)
	PREINIT:
	STRLEN n_a;
	CODE:
		int i;
		char *argv[items+1];
		argv[0] = prog;
		for(i=0; i<items; i++) {
			argv[i+1] = (char *)SvPV(ST(i), n_a);
		}
		parsecmdline(items+1, argv);


int
displayVersion()
	CODE:
		RETVAL = displayVersion;
	OUTPUT:
	RETVAL


char *
getConfigFileName()
	CODE:
		RETVAL = configfile;
	OUTPUT:
	RETVAL


char *
COPYVER()
	CODE:
		RETVAL = COPYVER;
	OUTPUT:
	RETVAL


MODULE = Netl			PACKAGE = Netl::Resolve


char *
ip2string(ipaddr)
	unsigned int	ipaddr
	CODE:
		RETVAL = ip2string(htonl(ipaddr));
	OUTPUT:
	RETVAL


MODULE = Netl			PACKAGE = Netl::Dump


void
_dumpdata(data, size)
	unsigned char *data
	size_t size
	CODE:
		netl_io_dumpf(data, size, stdout);

void
_dumpdatafile(data, size, FP)
	unsigned char *data
	size_t size
	FILE *FP
	CODE:
		netl_io_dumpf(data, size, FP);

MODULE = Netl			PACKAGE = Netl::Config


void
preconfig()
	CODE:
		netl_config_pre();

void
postconfig()
	CODE:
		netl_config_post();


void
_readconfig(confname, nbg)
	char *confname
	int nbg
	CODE:
		netl_config_readfile(confname, nbg);


	
void
clearconfig()
	CODE:
		netl_config_clear();


void
set_netl_nmopen_pretend(value)
	int value
	CODE:
		netl_nmopen_pretend = value;

void
parseconfigline(buff)
	char *buff
	CODE:
		netl_config_parseline(buff);


char *
configfile()
	CODE:
		RETVAL = configfile;
	OUTPUT:
	RETVAL



char *
netdevice()
	CODE:
		RETVAL = netdevice;
	OUTPUT:
	RETVAL

MODULE = Netl			PACKAGE = Netl::Catch


void
prepare(fd)
	int fd
	CODE:
		netl_catch_prepare(fd);


void
catch()
	PREINIT:
		ret_entry *re;
	PPCODE:
		re = netl_catch_catch();
		if(re == NULL) {
			/* nothing */
		} else if(re->packet_len == -1) {
			EXTEND(SP, 2);
			PUSHs(sv_2mortal(newSVpvn("-1", 2)));
			PUSHs(sv_2mortal(newSVpvn("died", 4)));
		} else if(re->packet_len == -2) {
			EXTEND(SP, 2);
			PUSHs(sv_2mortal(newSVpvn("-2", 2)));
			PUSHs(sv_2mortal(newSVpvn(re->name, strlen(re->name))));
		} else {
			EXTEND(SP, 2);
			PUSHs(sv_2mortal(newSVpv(re->name, strlen(re->name))));
			PUSHs(sv_2mortal(newSVpvn(re->packet, re->packet_len)));
		}

int
fork_a_netl(prog, ...)
	char *prog;
	PREINIT:
	STRLEN n_a;
	CODE:
		int i;
		char *argv[items+1];
		argv[0] = prog;
		for(i=1; i<items; i++) {
			argv[i] = (char *)SvPV(ST(i), n_a);
		}
		argv[i] = NULL;
		RETVAL = netl_catch_fork(prog, argv);
	OUTPUT:
	RETVAL
