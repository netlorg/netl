#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <netl/api.h>

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

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
	if (strEQ(name, "MAXICMP6TYPE"))
#ifdef MAXICMP6TYPE
	    return MAXICMP6TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MAXICMPCODE"))
#ifdef MAXICMPCODE
	    return MAXICMPCODE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MAXICMPTYPE"))
#ifdef MAXICMPTYPE
	    return MAXICMPTYPE;
#else
	    goto not_there;
#endif
	break;
    case 'N':
	if (strEQ(name, "NETL_API_H"))
#ifdef NETL_API_H
	    return NETL_API_H;
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


MODULE = Netl		PACKAGE = Netl		


double
constant(name,arg)
	char *		name
	int		arg



int
netl(dev)
	char *		dev
	CODE:
		RETVAL = netl(dev);
	OUTPUT:
	RETVAL


MODULE = Netl		PACKAGE = Netl::Guts


int
_get_yy_line_number()
	CODE:
		RETVAL = netl_guts_yy_line_number;
	OUTPUT:
	RETVAL


void
_set_yy_line_number(value)
	int		value
	CODE:
		netl_guts_yy_line_number = value;


MODULE = Netl		PACKAGE = Netl::Config

void
readfile(filename)
	char *		filename
	CODE:
		netl_config_readfile(filename, 1);


void
parseline(line)
	char *		line
	CODE:
		netl_config_parseline(line);


void
pre()
	CODE:
		netl_config_pre();


void
post()
	CODE:
		netl_config_post();


void
clear()
	CODE:
		netl_config_clear();

MODULE = Netl		PACKAGE = Netl::Catch

void
prepare(fd)
	int		fd
	CODE:
		netl_catch_prepare(fd);


int
fork(prog, ...)
	char *prog;
	PREINIT:
	STRLEN n_a;
	CODE:
		int i;
		char *argv[items+1];
		argv[0] = prog;
		for(i=1; i<items; i++) {
			argv[i] = (char *) SvPV(ST(i), n_a);
		}
		argv[i] = NULL;
		RETVAL = netl_catch_fork(prog, argv);
	OUTPUT:
	RETVAL
	
void
catch()
	PREINIT:
		netl_catch_t *re;
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

MODULE = Netl		PACKAGE = Netl::Packet

void
check(dg, size)
	char *		dg
	size_t		size
	CODE:
		netl_packet_check(dg, size);

MODULE = Netl		PACKAGE = Netl::Generate

void
c(fp)
	FILE *		fp
	CODE:
		netl_generate_c(fp);	/* i really have no idea if this works */

MODULE = Netl		PACKAGE = Netl::IO

MODULE = Netl		PACKAGE = Netl::Resolve

MODULE = Netl		PACKAGE = Netl::Table

MODULE = Netl		PACKAGE = Netl::NM
