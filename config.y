%{

/*==============================================================================
| config.y
|   coded by Graham THE Ollis <ollisg@wwa.com>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@wwa.com>
|
|   This program is free software; you can redistribute it and/or modify
|   it under the terms of the GNU General Public License as published by
|   the Free Software Foundation; either version 2 of the License, or
|   (at your option) any later version.
|
|   This program is distributed in the hope that it will be useful,
|   but WITHOUT ANY WARRANTY; without even the implied warranty of
|   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|   GNU General Public License for more details.
|
|   You should have received a copy of the GNU General Public License
|   along with this program; if not, write to the Free Software
|   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  26 Mar 99  G. Ollis	Created module
|  02 Jul 99  G. Ollis	added bitmask support for ip addresses (ie. x.x.0.0/16)
|=============================================================================*/

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "netl/io.h"
#include "netl/resolve.h"
#include "netl/options.h"
#include "netl/lookup.h"
#include "netl/filter.h"

extern int line_number;

int yyparse(void);
static int yyerror(char *s);
int yylex(void);
static int modifyip(u32 *num, char *name);
static void detectf(void);
static void additem(struct configlist *l, struct configitem *c);

static struct configitem ci;

/*==============================================================================
| this swap is a bit of a haxor as we say in the old school
| if the compiler is smart, this will be really fast, and require
| no temp variable.  this works only for integers of any native size.
==============================================================================*/

#define swap(x, y)	x ^= y;\
			y ^= x;\
			x ^= y

#define new(fred)	strcpy(allocate(strlen(fred)+1), fred);

static u8 flag_bitwise_not(u8 flags);

%}

%union {
	union_thingie x;
	char *s;
	int i;
	u8 hw[6];
	union ip6addr ip6a;
}

%token CON_STR CON_INT
%token RULE_DEVICE RULE_DETECT RULE_ALIAS RULE_LISTEN RULE_T
%token FLD_NAME FLD_FLAG FLD_DSTPORT FLD_SRCPORT FLD_DSTIP FLD_SRCIP FLD_DSTHW FLD_SRCHW FLD_TYPE FLD_TYPE6 FLD_CODE
%token FLG PROT NL
%token KEY_IF KEY_AND KEY_OR

%%

start : 	lines
	|
	;

lines : 	lines line
	|	line
	;

op_if :		KEY_IF
	|
	;


rule_t_list :	NL RULE_T rule_t_list
	|	NL
	|
	;

line :		RULE_DEVICE str	str NL	{ netdevice = $<x.s>2; free($<x.s>3); }
	|	RULE_DETECT NL		{ detectf(); }
	|	RULE_ALIAS str str NL	{
						u32 ip;
						if(modifyip(&ip, $<x.s>3))
							addip($<x.s>2, ip);
						free($<x.s>2); free($<x.s>3);
					}
	|	RULE_LISTEN CON_INT NL	{
						listenport = htons($<x.i>2);
						lookup_filter("dcp", PROT_USER);
						free($<x.s>2);
					}
	|	RULE_LISTEN NL		{
						listenport = htons(47);
						lookup_filter("dcp", PROT_USER);
					}
	|	KEY_IF '(' flds ')' '{' PROT rule_t_list '}' NL
						{
							/* FIXME! */
						}
	|	RULE_T PROT op_if op_flds NL	{
						filt_mod *fm;
						action_mod *am;
						char *name = $<x.s>2;

						if(name[0] == '&')
							name++;

						ci.filtermod = fm = lookup_filter(name, 
							$<x.code>2);

						if($<x.code>1 != ACTION_IGNORE) {
							am = lookup_act($<x.s>1, $<x.code>1);
							ci.actionmod = am;
							ci.actionf = am->action;
							ci.action_done = am->action_done;
						} else { 
							ci.action_done = NULL;
							ci.actionf = NULL;
						}
						ci.action = $<x.code>1;
						ci.protocol = $<x.code>2;
						additem(fm->cf, &ci);
						memset(&ci, 0, sizeof(struct configitem));
						free($<x.s>1);
					}
	| 	NL
	|	error NL		{ yyerrok; }
	;

str :		CON_STR			{ $<x.s>$ = yylval.x.s; }
	|	CON_INT			{ $<x.s>$ = yylval.x.s; }
	|	RULE_DEVICE 		{ $<x.s>$ = new("device"); }
	|	RULE_DETECT		{ $<x.s>$ = new("detect"); }
	|	RULE_ALIAS		{ $<x.s>$ = new("alias"); }
	|	RULE_LISTEN		{ $<x.s>$ = new("listen"); }
	|	RULE_T			{ $<x.s>$ = yylval.x.s; }
	|	PROT			{ $<x.s>$ = yylval.x.s; }
	|	FLG			{ $<x.s>$ = yylval.x.s; }
	;

op_flds :	flds
	|	'(' flds ')'
	|
	;

flds :		flds fld
	|	flds KEY_AND fld	{ /* fixme! */ }
	|	flds KEY_OR fld
	|	fld
	;

fld :		op_not FLD_NAME str
			{
				if(ci.logname != NULL)
					free(ci.logname);
				ci.logname = $<x.s>3;
				if($<x.i>1) 
					err("warning: usage of `!' on name field is meaningless line %d", line_number);
			}
	|	op_not FLD_FLAG flgs
			{
				if($<x.i>1) {
					if($<x.code>3 == FLG_ALL)
						ci.tcp_flags_off = flag_bitwise_not(ci.tcp_flags_on);
					else
						ci.tcp_flags_off = $<i>3;
					ci.check_tcp_flags_off = TRUE;
				} else {
					if($<x.code>3 == FLG_ALL)
						ci.tcp_flags_on = flag_bitwise_not(ci.tcp_flags_off);
					else
						ci.tcp_flags_on = $<i>3;
					ci.check_tcp_flags_on = TRUE;
				}
			}
	|	op_not FLD_DSTPORT CON_INT
			{
				if($<x.i>1) {
					ci.dst_prt_not = htons($<x.i>3);
					ci.check_dst_prt_not = TRUE;
				} else {
					ci.dst_prt1 = ci.dst_prt2 = htons($<x.i>3);
					ci.check_dst_prt = TRUE;
				}
				free($<x.s>3);
			}
	|	op_not FLD_DSTPORT CON_INT '-' CON_INT
			{
				if($<x.i>1) {
					err("warning: not port ranges not yet implemented for `!' line %d", line_number);
				} else {
					ci.dst_prt1 = htons($<x.i>3);
					ci.dst_prt2 = htons($<x.i>5);
					if(ntohs(ci.dst_prt2) > ntohs(ci.dst_prt1))
						swap(	ci.dst_prt1,
							ci.dst_prt2);
					ci.check_dst_prt = TRUE;
				}
				free($<x.s>3);
				free($<x.s>5);
			}
	|	op_not FLD_SRCPORT CON_INT
			{
				if($<x.i>1) {
					ci.src_prt_not = htons($<x.i>3);
					ci.check_src_prt_not = TRUE;
				} else {
					ci.src_prt1 = ci.src_prt2 = htons($<x.i>3);
					ci.check_src_prt = TRUE;
				}
				free($<x.s>3);
			}
	|	op_not FLD_SRCPORT CON_INT '-' CON_INT
			{
				if($<x.i>1) {
					err("warning: not port ranges not yet implemented for  `!' line %d", line_number);
				} else {
					ci.src_prt1 = htons($<x.i>3);
					ci.src_prt2 = htons($<x.i>5);
					if(ntohs(ci.src_prt2) > ntohs(ci.src_prt1))
						swap(	ci.src_prt1,
							ci.src_prt2);
					ci.check_src_prt = TRUE;
				}
				free($<x.s>3);
				free($<x.s>5);
			}
	|	op_not FLD_DSTIP ip6addr
			{			/* GNR */
				if($<x.i>1) {
					ci.check_dst_ip_not = 1;
					memcpy(&(ci.dst_ip6_not), &$<ip6a>3, 16);
				} else {
					ci.check_dst_ip = 1;
					memcpy(&(ci.dst_ip6), &$<ip6a>3, 16);
				}
			}
	|	op_not FLD_DSTIP str op_bitmask
			{
				u32 mask = $<x.i>4;
				if($<x.i>1) {
					if((ci.check_dst_ip_not = modifyip(
						&ci.dst_ip_not, $<x.s>3))) {
						ci.dst_ip_not_mask = mask;
						ci.dst_ip_not &= mask;
					}
				} else {
					if((ci.check_dst_ip = modifyip(
						&ci.dst_ip, $<x.s>3))) {
						ci.dst_ip_mask = mask;
						ci.dst_ip &= mask;
					}
				}
				free($<x.s>3);
			}
	|	op_not FLD_SRCIP str op_bitmask
			{
				u32 mask = $<x.i>4;
				if($<x.i>1) {
					if((ci.check_src_ip_not = modifyip(
						&ci.src_ip_not, $<x.s>3))) {
						ci.src_ip_not_mask = mask;
						ci.src_ip &= mask;
					}
				} else {
					if((ci.check_src_ip = modifyip(
						&ci.src_ip, $<x.s>3))) {
						ci.src_ip_mask = mask;
						ci.src_ip &= mask;
					}
				}
				free($<x.s>3);
			}
	|	op_not FLD_DSTHW hw
			{
				if($<x.i>1) {
					ci.check_dst_hw_not = TRUE;
					memcpy(ci.dst_hw_not, $<hw>3, 6);
				} else {
					ci.check_dst_hw = TRUE;
					memcpy(ci.dst_hw, $<hw>3, 6);
				}
			}
	|	op_not FLD_SRCHW hw
			{
				if($<x.i>1) {
					ci.check_src_hw_not = TRUE;
					memcpy(ci.src_hw_not, $<hw>3, 6);
				} else {
					ci.check_src_hw = TRUE;
					memcpy(ci.src_hw, $<hw>3, 6);
				}
			}
	|	op_not FLD_TYPE str
			{
				int i, answer=-1;
				for(i=0; i<MAXICMPTYPE; i++) {
					if(!strcmp(icmptype[i].name, $<x.s>3)) {
						ci.icmp_type = 
						answer = icmptype[i].index;
						ci.check_icmp_type = TRUE;
					}
				}
				if(answer == -1) {
					err("illegal type value %s line %d",
						$<x.s>3, line_number);
				}
				free($<x.s>3);
			}
	|	op_not FLD_TYPE6 str
			{
				int i, answer=-1;
				if($<x.i>3 != -1) {
					ci.icmp_type = answer = $<x.i>3;
					ci.check_icmp_type = TRUE;
				} else for(i=0; i<MAXICMP6TYPE; i++) {
					if(!strcmp(icmp6type[i].name, $<x.s>3)) {
						ci.icmp_type = 
						answer = icmp6type[i].index;
						ci.check_icmp_type = TRUE;
					}
				}
				if(answer == -1) {
					err("illegal type value %s line %d",
						$<x.s>3, line_number);
				}
				free($<x.s>3);
			}
	|	op_not FLD_CODE str
			{
				int i, answer=-1;
				if($<x.i>3 != -1) {
					ci.icmp_code = answer = $<x.i>3;
					ci.check_icmp_code =TRUE;
				} else for(i=0; i<MAXICMPCODE; i++) {
					if(!strcmp(icmpcode[i].name, $<x.s>3)) {
						ci.icmp_code = 
						answer = icmpcode[i].index;
						ci.check_icmp_code = TRUE;
					}
				}
				if(answer == -1) {
					err("illegal code value %s line %d",
						$<x.s>3, line_number);
				}
				free($<x.s>3);
			}
	;

op_bitmask :	'/' CON_INT	
			{
				int num = $<x.i>2;
				int mask = 0xffffffff << (32-num);
				free($<x.s>2);
				/*log("num:%d, mask:%x", num, mask);*/
				$<x.i>$ = htonl(mask);
			}
	|	'/' '(' CON_INT '.' CON_INT '.' CON_INT '.' CON_INT ')'
			{
				u32 i;  char ip[4];
				ip[0] = $<x.i>3; free($<x.s>3);
				ip[1] = $<x.i>5; free($<x.s>5);
				ip[2] = $<x.i>7; free($<x.s>7);
				ip[3] = $<x.i>9; free($<x.s>9);
				memcpy(&i, ip, 4);
				$<x.i>$ = i;
			}
	|			{ $<x.i>$ = htonl(0xffffffff); }
	;

op_not :	'!'	{ $<x.i>$ = 1; }
	|		{ $<x.i>$ = 0; }
	;

flgs :		flgs ',' flg	{ $<i>$ = $<i>1 | $<i>3; }
	|	flg		{ $<i>$ = $<i>1; }
	;

flg :		FLG	{	/* sigh */
				union { flagbyte x; u8 i; } fb;

				fb.i = 0;

				switch($<x.code>1) {
					case FLG_URG : fb.x.urg = TRUE; break;
					case FLG_ACK : fb.x.ack = TRUE; break;
					case FLG_PSH : fb.x.psh = TRUE; break;
					case FLG_RST : fb.x.rst = TRUE; break;
					case FLG_SYN : fb.x.syn = TRUE; break;
					case FLG_FIN : fb.x.fin = TRUE; break;
					case FLG_ALL :
						fb.x.urg = fb.x.ack = fb.x.psh =
						fb.x.rst = fb.x.syn = fb.x.fin =
							TRUE;
						break;
				}
				$<i>$ = fb.i;
				free($<x.s>1);
			}
	;

hw :		CON_INT ':' CON_INT ':' CON_INT ':' 
		CON_INT ':' CON_INT ':' CON_INT
			{
				$<hw>$[0] = $<x.h>1;	free($<x.s>1);
				$<hw>$[1] = $<x.h>3;	free($<x.s>3);
				$<hw>$[2] = $<x.h>5;	free($<x.s>5);
				$<hw>$[3] = $<x.h>7;	free($<x.s>7);
				$<hw>$[4] = $<x.h>9;	free($<x.s>9);
				$<hw>$[5] = $<x.h>11;	free($<x.s>11);
			}
	;

ip6addr :	'[' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':'
		op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ']'
			{
				$<ip6a.byte>$[0] = $<x.h>2;
				$<ip6a.byte>$[1] = $<x.h>4;
				$<ip6a.byte>$[2] = $<x.h>6;
				$<ip6a.byte>$[3] = $<x.h>8;
				$<ip6a.byte>$[4] = $<x.h>10;
				$<ip6a.byte>$[5] = $<x.h>12;
				$<ip6a.byte>$[6] = $<x.h>14;
				$<ip6a.byte>$[7] = $<x.h>16;
			}
	;

op_con_int :	CON_INT	{ $<x.h>$ = $<x.h>1; free($<x.s>1); }
	|		{ $<x.h>$ = 0; }

%%

/*==============================================================================
| simple, but effective error reporting.  hey.  get off my back.
==============================================================================*/

static int
yyerror(char *s)
{
	err("%s on line %d", s, line_number);

	return 1;
}

/*==============================================================================
| globals
==============================================================================*/

signed int listenport = -1;	/* oh my gosh, i'm wasting 15 BITS!!!! */
				/* actually, 31.  nevermind.  		*/

/*==============================================================================
| clean up all the config data and make it ready for a new config file read.
==============================================================================*/

static void
freelist(struct configlist *cl)
{
	int i;

	for(i=0; i<cl->index; i++) {
		if(cl->c[i].logname != NULL)
			free(cl->c[i].logname);
		if(cl->c[i].format != NULL)
			free(cl->c[i].format);
	}
	free(cl->c);
	cl->c = NULL;
}

void
clearconfig(void)
{
	int i;

	/* reset the action table */
	for(i=0; i<num_acts; i++) {
		free(acts[i].name);
		nmclose(acts[i].handle);
	}
	num_acts = max_acts = 0;
	acts = NULL;

	/* reset the filter table */
	for(i=0; i<num_filters; i++) {
		freelist(filters[i].cf);
		free(filters[i].name);
		nmclose(filters[i].handle);
	}
	num_filters = max_filters = 0;
	filters = NULL;
}

/*==============================================================================
| set initial list size
==============================================================================*/

void
set_config_list(struct configlist *l)
{
	l->c=(struct configitem *) allocate(sizeof(struct configitem)*100);
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

	tmp=(struct configitem *) allocate(memorysize);

	memcpy(tmp, l->c, memorysize);
	free(l->c);
	l->c = tmp;
	l->size = size;
}

/*==============================================================================
| detect hostname/IP number
==============================================================================*/

static void
detectf(void)
{
	char			buff[255];
	struct hostent *	herhost;
	union			{ u32 i; u8 c[4]; } addr;

	addip("localhost", LOCALHOST_IP);
	addr.i = searchbyname("localhost");
	gethostname(buff, 255);
	if((herhost = gethostbyname(buff)) != NULL) {
		addip("local", *((u32 *) herhost->h_addr_list[0]) );
		addip(buff, *((u32 *) herhost->h_addr_list[0]) );
	} else {
		err("warning: could not detect hostname");
	}
}

/*==============================================================================
| add an item
==============================================================================*/

static void
additem(struct configlist *l, struct configitem *c)
{
	if(l->index == l->size)
		resizelist(l, l->size * 2);
	memcpy(	(char *) &l->c[l->index++], 
		(char *) c,
		sizeof(struct configitem));
}

/*==============================================================================
| what happens before and after you do the config stuff.
|
|  it used to be that these actually did something.  in the near future i may 
|  remove them all together.  time will tell.
==============================================================================*/

void
preconfig(void)
{
}

void
postconfig(void)
{
}

/*==============================================================================
| readconfig(char *prog)
|
|  this function reads the config file and alters the config structure
|  apropriately
==============================================================================*/

#ifdef NO_SYSLOGD
void
readconfig(char *confname)
#endif
#ifndef NO_SYSLOGD
void
readconfig(char *confname, int nbg)
#endif
{
	extern FILE *yyin;

	memset(&ci, 0, sizeof(struct configitem));
	#ifndef NO_SYSLOGD
		swap(nbg, noBackground);
	#endif

	if((yyin=fopen(confname, "r")) == NULL) {       /* open, damn it, open */
		err("error: opening %s for read, die", confname);
						      /* magnus, i want the 
							 matrix. */
		exit(2);			      /* NEVER! */
	}

	preconfig();
	yyparse();
	postconfig();
	/*printconfig();*/
	/*printalias();*/

	#ifndef NO_SYSLOGD
		swap(nbg, noBackground);
	#endif

	fclose(yyin);
}

void
parseconfigline(char *s)
{
	int filedes[2];
	extern FILE *yyin;

	if(pipe(filedes) == -1) {
		err("unable to open pipe!");
		exit(2);
	}

	if(write(filedes[1], s, strlen(s)) == -1 ||
	   write(filedes[1], "\n", 1) == -1) {
		err("unable to write to pipe! (%s)", strerror(errno));
		exit(2);
	}

	if(close(filedes[1]) == -1) {
		err("unable to close write end of pipe!");
		exit(2);
	}

	yyin = fdopen(filedes[0], "r");
	if(yyin == NULL) {
		err("unable to fdopen() pipe!");
		exit(2);
	}

	yyparse();

	fclose(yyin);
}

/*==============================================================================
| ip
|
|  this ... this is the most confusing piece of code i have ever seen in my
|  life.  i have no idea what it does, *exactly*  it... does a name lookup
|  or something odd, i can't quite figure out.  i certainly wish i had commented
|  it better when i wrote it, because i can't imagine what i was smoking when
|  i wrote it.  *shrug*
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

	buff = allocate(strlen(name) + 1);
	strcpy(buff, name);

	element = strtok(buff, ".");
		while(i < 4) {
			if(element == NULL) {

				err("warning: could not parse ip address %s (line %d)",
					name, line_number);
				return FALSE;
			}
		tmp[i++] = atoi(element);
		element = strtok(NULL, ".");
	}

	return TRUE;
}

static u8
flag_bitwise_not(u8 flags)
{
	union { u8 u; flagbyte fb; } f;
	f.u = flags;
	f.fb.fin = !f.fb.fin;
	f.fb.syn = !f.fb.syn;
	f.fb.rst = !f.fb.rst;
	f.fb.psh = !f.fb.psh;
	f.fb.ack = !f.fb.ack;
	f.fb.urg = !f.fb.urg;
	return f.u;
}

/*==============================================================================
| printconfig - print out config options as a debugging option thing.
==============================================================================*/

void
printconfig(void)
{
	err("printconfig() no longer implemented");
}

