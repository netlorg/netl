%{

#ifdef NETL_CONFIG_Y_C

/*==============================================================================
| config.y
|   coded by Graham THE Ollis <ollisg@netl.org>
|
|   Copyright (C) 1997 Graham THE Ollis <ollisg@netl.org>
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
|  20 Oct 99  G. Ollis	added a perl version.  right in this file.  caused all
|			kinds of problems...
|=============================================================================*/

/*

from the Makefile:

# this here is a haxor of supreme dimensions.

# config.y contains the parser for libnetl and the netl executable, in
# addition to the perl version of the parser used by tknetl.  right now there
# are macros NETL_CONFIG_Y_C and NETL_CONFIG_Y_PERL to indicate the language
# as appropriate.  however, the C version uses bison and the perl version uses
# a specially modified version of byacc.  joe random shouldn't have to run
# byacc when downloading the netl dist, as it is some what rare.  this is the
# rule for updateing the perl version of the parser.  it doesn't get run by
# default because of the above reasons.  unless you modify the the parser in
# an extremely anoying way, it shouldn't need updating anyway.

# the special byacc is available on CPAN somewhere under the /src directory,
# i believe.

*/

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
| this swap is a bit of a haxor as we say in the old skuhl
==============================================================================*/

#define swap(x, y)	x ^= y; \
			y ^= x; \
			x ^= y

#define new(fred)	strcpy(allocate(strlen(fred)+1), fred);

static u8 flag_bitwise_not(u8 flags);

#endif

#ifdef NETL_CONFIG_Y_PERL

/*

BEGIN { $warning_save = $^W; $^W = 0 }
package Netl::Config::Parser;

#===============================================================================
# do not attempt to modify Parser.pm by had, it is generated from config.y
# in the netl base distribution.
# there are a few globals which are set after the parser completes.
#
#	@rules		. list of rules [ [action ...], protocol, fields ... ]
#	$libdir		. final library directory specified (iff specified)
#	$dumpdir	. final dump directory specified (iff specified)
#	$listenport	. argument of listen directive
#	$detect		. true iff detect directive appears
#	%alias		. IP aliases
#===============================================================================

*/

#endif

%}

%union {
	union_thingie x;
	char *s;
	int i;
	u8 hw[6];
	union ip6addr ip6a;
}

%token CON_STR CON_INT
%token RULE_DEVICE RULE_DETECT RULE_ALIAS RULE_LISTEN RULE_T RULE_DIR_LIB RULE_DIR_DUMP
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


rule_t_list :	RULE_T ',' rule_t_list
					{
#ifdef NETL_CONFIG_Y_C
						if($<x.code>1 != ACTION_IGNORE) {
							action_mod *new, *am;
							int size = ($<x.i>3) + 1;
							am = lookup_act($<x.s>1, $<x.code>1);
							new = allocate(sizeof(action_mod) * size);
							if(size>1)
								memcpy(&new[1], $<x.s>3, ($<x.i>3) * sizeof(action_mod));
							memcpy(new, am, sizeof(action_mod));
							$<x.s>$ = (char *) new;
							$<x.i>$ = size;
						} else { 
							$<x.s>$ = $<x.s>3;
							$<x.i>$ = $<x.i>3;
						}
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						my $fred = $3;
						$$ = [ $1, @{$fred} ];
*/
#endif
					}
	|	RULE_T			{
#ifdef NETL_CONFIG_Y_C
						if($<x.code>1 != ACTION_IGNORE) {
							$<x.s>$ = (char *) lookup_act($<x.s>1, $<x.code>1);
							$<x.i>$ = 1;
						} else { 
							$<x.s>$ = (char *) NULL;
							$<x.i>$ = 0;
						}
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = [ $1 ];
*/
#endif
					}
	;

line :		RULE_DEVICE str	str NL	{ 
#ifdef NETL_CONFIG_Y_C
						netdevice = $<x.s>2; free($<x.s>3);
#endif
					}
	|	RULE_DETECT NL		{
#ifdef NETL_CONFIG_Y_C
						detectf();
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$detect = 1;
*/
#endif
					}
	|	RULE_ALIAS str str NL	{
#ifdef NETL_CONFIG_Y_C
						u32 ip;
						if(modifyip(&ip, $<x.s>3))
							addip($<x.s>2, ip);
						free($<x.s>2); free($<x.s>3);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$alias{ $2 } = $3;
*/
#endif
					}
	|	RULE_LISTEN CON_INT NL	{
#ifdef NETL_CONFIG_Y_C
						listenport = htons($<x.i>2);
						lookup_filter("dcp", PROT_USER);
						free($<x.s>2);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$listenport = $2;
*/
#endif
					}
	|	RULE_DIR_LIB CON_STR NL	
					{
#ifdef NETL_CONFIG_Y_C

						so_path = $<x.s>2;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$libdir = $2;
*/
#endif
					}
	|	RULE_DIR_DUMP CON_STR NL
					{
#ifdef NETL_CONFIG_Y_C

						dump_dir = $<x.s>2;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$dumpdir = $2;
*/
#endif
					}
	|	RULE_LISTEN NL		{
#ifdef NETL_CONFIG_Y_C

						listenport = htons(47);
						lookup_filter("dcp", PROT_USER);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$listenport = 47;
*/
#endif
					}
	|	'<' rule_t_list '>' PROT op_if op_flds NL
					{
#ifdef NETL_CONFIG_Y_C
						filt_mod *fm;
						char *name = $<x.s>4;

						if(name[0] == '&')
							name++;

						ci.filtermod = fm = lookup_filter(name, 
							$<x.code>4);

						ci.action = ACTION_MULT;
						ci.actionmod = (action_mod *) $<x.s>2;
						ci.num_actionmod = $<x.i>2;

						ci.protocol = $<x.code>2;
						additem(fm->cf, &ci);
						memset(&ci, 0, sizeof(struct configitem));
						free($<x.s>1);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						my $flds = $6;
				push @rules, 
					[ $line_number, $2, $4, 
						flds2hash(@{ $flds }) ];
*/
#endif
					}
	|	RULE_T PROT op_if op_flds NL
					{
#ifdef NETL_CONFIG_Y_C
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
						} 
						ci.action = $<x.code>1;
						ci.protocol = $<x.code>2;
						ci.num_actionmod = 1;
						additem(fm->cf, &ci);
						memset(&ci, 0, sizeof(struct configitem));
						free($<x.s>1);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						my $flds = $4;
				push @rules, 
					[ $line_number, [ $1 ], $2, 
						flds2hash(@{ $flds }) ];
*/
#endif
					}
	| 	NL
	|	error NL		{ yyerrok; }
	;

str :		CON_STR			{ 
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = yylval.x.s;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	CON_INT			{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = yylval.x.s;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	RULE_DEVICE 		{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = new("device");
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	RULE_DETECT		{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = new("detect");
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	RULE_ALIAS		{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = new("alias");
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	RULE_LISTEN		{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = new("listen");
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	RULE_T			{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = yylval.x.s;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	PROT			{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = yylval.x.s;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	FLG			{
#ifdef NETL_CONFIG_Y_C
						$<x.s>$ = yylval.x.s;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	;

op_flds :	flds			{
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $1;
*/
#endif
					}
	|	'(' flds ')'
					{
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = $2;
*/
#endif
					}
	|
					{
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = [ ];
*/
#endif
					}
	;

flds :		flds fld		{
#ifdef NETL_CONFIG_Y_PERL
/*
						my $fred = $1;
						$$ = [ @{$fred}, $2 ];
*/
#endif
					}
	|	flds KEY_AND fld	{
#ifdef NETL_CONFIG_Y_PERL
/*
						my $fred = $1;
						$$ = [ @{$fred}, $3 ];
*/
#endif
					}
	|	flds KEY_OR fld		{
#ifdef NETL_CONFIG_Y_PERL
/*
						die "or is unimplemented.";
*/
#endif
					}
	|	fld			{
#ifdef NETL_CONFIG_Y_PERL
/*
						$$ = [ $1 ];
*/
#endif
					}
	;

fld :		op_not FLD_NAME str
			{
#ifdef NETL_CONFIG_Y_C
				if(ci.logname != NULL)
					free(ci.logname);
				ci.logname = $<x.s>3;
				if($<x.i>1) 
					err("warning: usage of `!' on name field is meaningless line %d", line_number);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = [ 'name', $3 ];
*/
#endif
			}
	|	op_not FLD_FLAG flgs
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!flag', $3 ];
				} else {
					$$ = [ 'flag', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_DSTPORT CON_INT
			{
#ifdef NETL_CONFIG_Y_C
				if($<x.i>1) {
					ci.dst_prt_not = htons($<x.i>3);
					ci.check_dst_prt_not = TRUE;
				} else {
					ci.dst_prt1 = ci.dst_prt2 = htons($<x.i>3);
					ci.check_dst_prt = TRUE;
				}
				free($<x.s>3);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!dstport', $3, $3 ];
				} else {
					$$ = [ 'dstport', $3, $3 ];
				}
*/
#endif
			}
	|	op_not FLD_DSTPORT CON_INT '-' CON_INT
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!dstport', $3, $5 ];
				} else {
					$$ = [ 'dstport', $3, $5 ];
				}
*/
#endif
			}
	|	op_not FLD_SRCPORT CON_INT
			{
#ifdef NETL_CONFIG_Y_C
				if($<x.i>1) {
					ci.src_prt_not = htons($<x.i>3);
					ci.check_src_prt_not = TRUE;
				} else {
					ci.src_prt1 = ci.src_prt2 = htons($<x.i>3);
					ci.check_src_prt = TRUE;
				}
				free($<x.s>3);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!srcport', $3, $3 ];
				} else {
					$$ = [ 'srcport', $3, $3 ];
				}
*/
#endif
			}
	|	op_not FLD_SRCPORT CON_INT '-' CON_INT
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!srcport', $3, $5 ];
				} else {
					$$ = [ 'srcport', $3, $5 ];
				}
*/
#endif
			}
	|	op_not FLD_DSTIP ip6addr
			{
#ifdef NETL_CONFIG_Y_C
						/* GNR */
				if($<x.i>1) {
					ci.check_dst_ip_not = 1;
					memcpy(&(ci.dst_ip6_not), &$<ip6a>3, 16);
				} else {
					ci.check_dst_ip = 1;
					memcpy(&(ci.dst_ip6), &$<ip6a>3, 16);
				}
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!ip6addr', $3 ];
				} else {
					$$ = [ 'ip6addr', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_DSTIP str op_bitmask
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!dstip', $3, $4 ];
				} else {
					$$ = [ 'dstip', $3, $4 ];
				}
*/
#endif
			}
	|	op_not FLD_SRCIP str op_bitmask
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!srcip', $3, $4 ];
				} else {
					$$ = [ 'srcip', $3, $4 ];
				}
*/
#endif
			}
	|	op_not FLD_DSTHW hw
			{
#ifdef NETL_CONFIG_Y_C
				if($<x.i>1) {
					ci.check_dst_hw_not = TRUE;
					memcpy(ci.dst_hw_not, $<hw>3, 6);
				} else {
					ci.check_dst_hw = TRUE;
					memcpy(ci.dst_hw, $<hw>3, 6);
				}
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!dsthw', $3 ];
				} else {
					$$ = [ 'dsthw', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_SRCHW hw
			{
#ifdef NETL_CONFIG_Y_C
				if($<x.i>1) {
					ci.check_src_hw_not = TRUE;
					memcpy(ci.src_hw_not, $<hw>3, 6);
				} else {
					ci.check_src_hw = TRUE;
					memcpy(ci.src_hw, $<hw>3, 6);
				}
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!srchw', $3 ];
				} else {
					$$ = [ 'srchw', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_TYPE str
			{
#ifdef NETL_CONFIG_Y_C
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
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!type', $3 ];
				} else {
					$$ = [ 'type', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_TYPE6 str
			{
#ifdef NETL_CONFIG_Y_C
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
#endif

#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!type6', $3 ];
				} else {
					$$ = [ 'type6', $3 ];
				}
*/
#endif
			}
	|	op_not FLD_CODE str
			{
#ifdef NETL_CONFIG_Y_C
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
#endif

#ifdef NETL_CONFIG_Y_PERL
/*
				if($1) {
					$$ = [ '!code', $3 ];
				} else {
					$$ = [ 'code', $3 ];
				}
*/
#endif
			}
	;

op_bitmask :	'/' CON_INT	
			{
#ifdef NETL_CONFIG_Y_C
				int num = $<x.i>2;
				int mask = 0xffffffff << (32-num);
				free($<x.s>2);
				/*log("num:%d, mask:%x", num, mask);*/
				$<x.i>$ = htonl(mask);
#endif

#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = (0xffffffff) << (32 - $2);
*/
#endif
			}
	|	'/' '(' CON_INT '.' CON_INT '.' CON_INT '.' CON_INT ')'
			{
#ifdef NETL_CONFIG_Y_C
				u32 i;  char ip[4];
				ip[0] = $<x.i>3; free($<x.s>3);
				ip[1] = $<x.i>5; free($<x.s>5);
				ip[2] = $<x.i>7; free($<x.s>7);
				ip[3] = $<x.i>9; free($<x.s>9);
				memcpy(&i, ip, 4);
				$<x.i>$ = i;
#endif

#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = $3 * 0x1000000 +
				     $5 *   0x10000 +
				     $7 *     0x100 +
				     $9;
*/
#endif
			}
	|		{
#ifdef NETL_CONFIG_Y_C
				$<x.i>$ = htonl(0xffffffff);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = 0xffffffff;
*/
#endif
			}
	;

op_not :	'!'	{
#ifdef NETL_CONFIG_Y_C
				$<x.i>$ = 1;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = 1;
*/
#endif
			}
	|		{
#ifdef NETL_CONFIG_Y_C
				$<x.i>$ = 0;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = 0;
*/
#endif
			}
	;

flgs :		flgs ',' flg
			{
#ifdef NETL_CONFIG_Y_C
				$<i>$ = $<i>1 | $<i>3;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				my $fred = $1;
				$$ = [ @{$fred}, $3 ];
*/
#endif
			}
	|	flg	{
#ifdef NETL_CONFIG_Y_C
				$<i>$ = $<i>1;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = [ $1 ];
*/
#endif
			}
	;

flg :		FLG	{
#ifdef NETL_CONFIG_Y_C
				/* sigh */
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
#endif

#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = $1;
*/
#endif
			}
	;

hw :		CON_INT ':' CON_INT ':' CON_INT ':' 
		CON_INT ':' CON_INT ':' CON_INT
			{
#ifdef NETL_CONFIG_Y_C
				$<hw>$[0] = $<x.h>1;	free($<x.s>1);
				$<hw>$[1] = $<x.h>3;	free($<x.s>3);
				$<hw>$[2] = $<x.h>5;	free($<x.s>5);
				$<hw>$[3] = $<x.h>7;	free($<x.s>7);
				$<hw>$[4] = $<x.h>9;	free($<x.s>9);
				$<hw>$[5] = $<x.h>11;	free($<x.s>11);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = [ $1, $3, $5, $7, $9, $11 ];
*/
#endif
			}
	;

ip6addr :	'[' op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ':'
		op_con_int ':' op_con_int ':' op_con_int ':' op_con_int ']'
			{
#ifdef NETL_CONFIG_Y_C
				$<ip6a.byte>$[0] = $<x.h>2;
				$<ip6a.byte>$[1] = $<x.h>4;
				$<ip6a.byte>$[2] = $<x.h>6;
				$<ip6a.byte>$[3] = $<x.h>8;
				$<ip6a.byte>$[4] = $<x.h>10;
				$<ip6a.byte>$[5] = $<x.h>12;
				$<ip6a.byte>$[6] = $<x.h>14;
				$<ip6a.byte>$[7] = $<x.h>16;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = [ $2,  $4,  $6,  $8, $10, $12, $14, $16 ];
*/
#endif
			}
	;

op_con_int :	CON_INT
			{
#ifdef NETL_CONFIG_Y_C

				$<x.h>$ = $<x.h>1; free($<x.s>1);
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = $1;
*/
#endif
			}
	|		{
#ifdef NETL_CONFIG_Y_C
				$<x.h>$ = 0;
#endif
#ifdef NETL_CONFIG_Y_PERL
/*
				$$ = 0;
*/
#endif
			}

%%

#ifdef NETL_CONFIG_Y_C

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
		die(2, "error opening %s for read", confname);
						      /* magnus, i want the 
							 matrix. */
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
		die(2, "unable to open pipe!");
	}

	if(write(filedes[1], s, strlen(s)) == -1 ||
	   write(filedes[1], "\n", 1) == -1) {
		die(2, "unable to write to pipe! (%s)", strerror(errno));
	}

	if(close(filedes[1]) == -1) {
		die(2, "unable to close write end of pipe!");
	}

	yyin = fdopen(filedes[0], "r");
	if(yyin == NULL) {
		die(2, "unable to fdopen() pipe!");
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

/*==============================================================================
| printconfig - print out config options as a debugging option thing.
==============================================================================*/

char *
netl_config_y_2str(struct configitem *ci)
{	/* i may not actually need this. */
	#define BUFF_LEN 4096
	static char buffer[BUFF_LEN];
	char *action;
	char *prot;
	char prot_buffer[BUFF_LEN];
	char action_buffer[BUFF_LEN];
	int i;

	switch(ci->action) {
		case ACTION_LOG : action = "log"; break;
		case ACTION_DUMP : action = "dump"; break;
		case ACTION_IGNORE : action = "ignore"; break;
		case ACTION_DL : action = "dl"; break;
		case ACTION_NULL : action = "null"; break;
		case ACTION_PIPE : action = "pipe"; break;

		case ACTION_MULT :
			action = action_buffer;
			action_buffer[0] = '<';
			action_buffer[1] = 0;
			for(i=0; i<ci->num_actionmod; i++) {
				strcat(action_buffer, ci->actionmod[i].name);
				if(i < ci->num_actionmod-1)
					strcat(action_buffer, ",");
			}
			strcat(action_buffer, ">");
			break;

		case ACTION_USER :
			action = action_buffer;
			action_buffer[0] = '&';
			action_buffer[1] = 0;
			strcat(action_buffer, ci->actionmod->name);
			break;

		default :
			action = action_buffer;
			sprintf(action_buffer, "<-unknown %d->", ci->action);
			break;

	}

	switch(ci->protocol) {

		case PROT_TCP  : prot = "tcp";  break;
		case PROT_UDP  : prot = "udp";  break;
		case PROT_ICMP : prot = "icmp"; break;
		case PROT_IGNP : prot = "ignp"; break;
		case PROT_RAW  : prot = "raw";  break;
		case PROT_IP   : prot = "ip";   break;

		case PROT_TCP4  : prot = "tcp4";  break;
		case PROT_UDP4  : prot = "udp4";  break;
		case PROT_ICMP4 : prot = "icmp4"; break;
		case PROT_IGNP4 : prot = "ignp4"; break;
		case PROT_IP4   : prot = "ip4";   break;

		case PROT_TCP6  : prot = "tcp6";  break;
		case PROT_UDP6  : prot = "udp6";  break;
		case PROT_ICMP6 : prot = "icmp6"; break;
		case PROT_IGNP6 : prot = "ignp6"; break;
		case PROT_IP6   : prot = "ip6";   break;

		case PROT_USER  :
			prot = prot_buffer;
			sprintf(prot_buffer, "@%s", ci->filtermod->name);
			break;

		default :
			prot = prot_buffer;
			sprintf(prot_buffer, "@unknown(%d)", ci->protocol);
			break;
	}

	sprintf(buffer, "%s %s ", action, prot);
	if(ci->logname != NULL) {
		strcat(buffer, "name=\"");
		strcat(buffer, ci->logname);
		strcat(buffer, "\" ");
	}

	return buffer;
}

#endif

#ifdef NETL_CONFIG_Y_PERL
/*

BEGIN {
	$regex = qr{^
			(\n)|				# 1 new line
			([ \t]+)|			# 2 white space
			(\#.*?\n)|			# 3 comment
			(".*?")|			# 4 string
			(\(|\{|\)|\})|			# 5 brace
			(\;)|				# 6 thingie
			(if|and|\&\&|or|\|\||
			 device|detect|alias|listen|
			 dir[ ]lib|dir[ ]dump|
			 ignore|log|dump|dl|null|
			 pipe)|				# 7 other thingies
			(\@[a-zA-Z0-9\._]+)|		# 8 $ACTION_USER 
			(raw|tcp|icmp|ignp|udp|ip|
			 tcp4|icmp4|ignp4|udp4|ip4|
			 tcp6|icmp6|ignp6|udp6|ip6)|	# 9 protocols
			(\&[a-zA-Z0-9\._]+)|		# 10 $PROT_USER
			(
			 (?:
				name|flag|
				(?:dst|src)(?:port|ip|hw)|
				type|type6|code|
			 )=)|				# 11 $FLD_*
			(urg|ack|psh|rsh|syn|fin|all)|	# 12 FLG
			([a-zA-Z0-9\._]+)|		# 13 CON_STR
			([0-9A-Fa-f]+)|			# 14 number
			(.)				# 15 unhandled character
			}imx;
}

%yylex = (
	'if'		=>	$KEY_IF,
	'and'		=>	$KEY_AND,
	'&&'		=>	$KEY_AND,
	'or'		=>	$KEY_OR,
	'||'		=>	$KEY_OR,
	'device'	=>	$RULE_DEVICE,
	'detect'	=>	$RULE_DETECT,
	'alias'		=>	$RULE_ALIAS,
	'listen'	=>	$RULE_LISTEN,
	'dir lib'	=>	$RULE_DIR_LIB,
	'dir dump'	=>	$RULE_DIR_DUMP,
	'ignore'	=>	$RULE_T,
	'log'		=>	$RULE_T,
	'dump'		=>	$RULE_T,
	'dl'		=> 	$RULE_T,
	'null'		=>	$RULE_T,
	'pipe'		=>	$RULE_T,
	'name='		=>	$FLD_NAME,
	'flag='		=>	$FLD_FLAG,
	'dstport='	=>	$FLD_DSTPORT,
	'srcport='	=>	$FLD_SRCPORT,
	'dstip='	=>	$FLD_DSTIP,
	'srcip='	=>	$FLD_SRCIP,
	'dsthw='	=>	$FLD_DSTHW,
	'srchw='	=>	$FLD_SRCHW,
	'type='		=>	$FLD_TYPE,
	'type6='	=>	$FLD_TYPE6,
	'code='		=>	$FLD_CODE,
	'urg'		=>	$FLG,
	'ack'		=>	$FLG,
	'psh'		=>	$FLG,
	'rst'		=>	$FLG,
	'syn'		=>	$FLG,
	'fin'		=>	$FLG,
	'all'		=>	$FLG,
);

sub yylex {
	($id, $val) = _yylex(@_);
	#print STDERR "id:$id, val:$val\n";
	return ($id, $val);
}

sub _yylex {
	if(defined @yylex_next) {
		my @save = @yylex_next;
		undef @yylex_next;
		return @save;
	}

	return 0 if $done;

	unless(defined $input) {
		$save = $/;
		$input = <STDIN>;
		$/ = $save;
		$line_number = 1;
		# @source = split /\n/m, $input;
	}

fred:	while($input ne '') {
		if($input =~ s/$regex//) {
			#=======================================================
			# $1 new line and $3 comment (both mean a \n)
			#=======================================================

			if(($1 ne '') or ($3 ne '') or ($6 ne '')) {
				$line_number++;
				return ($NL, '');
			}

			#=======================================================
			# $2 white space (ignore)
			#=======================================================

			next fred if $2 ne '';

			#=======================================================
			# $4 quotation
			#=======================================================

			if($4 ne '') {
				my $val = $4;
				$val =~ s/^"//;		# "
				$val =~ s/"$//;	# "
				return ($CON_STR, $val);
			}

			#=======================================================
			# $5 brace
			#=======================================================

			if($5 ne '') {
				return (ord($5), $5);
			}

			#=======================================================
			# $7 value-less returns
			#=======================================================

			if($7 ne '') {
				return ($yylex{$7}, $7);
			}

			#=======================================================
			# $8 user action
			#=======================================================

			if($8 ne '') {
				my $val = $8;
				$val =~ s/^\@//;
				return ($RULE_T, $val);
			}

			#=======================================================
			# $9 protocol
			#=======================================================

			if($9 ne '') {
				return ($PROT, $9);
			}

			#=======================================================
			# $10 user protocol
			#=======================================================

			if($10 ne '') {
				my $val = $10;
				$val =~ s/^\&//;
				return ($PROT, $val);
			}

			#=======================================================
			# $11 FIELD_*
			#=======================================================

			if($11 ne '') {
				return ($yylex{$11}, $11);
			}

			#=======================================================
			# $12 FLG_*
			#=======================================================

			if($12 ne '') {
				return ($yylex{$12}, $12);
			}

			#=======================================================
			# $14 number
			#=======================================================

			if($14 ne '') {
				return ($CON_INT, $14);
			}


			#=======================================================
			# $13 CON_STR
			#=======================================================

			if($13 ne '') {
				#printf "(\$CON_STR, \$13) = ($CON_STR, $13)\n";
				return ($CON_STR, $13);
			}

			#=======================================================
			# $15 all other non-matching characters
			#=======================================================

			return (ord($15), $15) if $15 ne '';

			die "lex pattern grabbed nothing!\n";
		} else {
			die "serious error, compilex regex replace failed!";
		}
	}
	$done = 1;
	return 0;
}

sub yyerror {
	printf(STDERR "$_[0] on line $line_number\n");
}

sub gparse {
	$input = shift;
	my $yyerror = $_[0] || \&yyerror;
	my $parser = Netl::Config::Parser->new(\&yylex, $yyerror, 0);
	$line_number = 1;
	my $save = $^W;
	$^W = 0;
	$parser->yyparse;
	$^W = $save;
}

sub flds2hash {
	my @list = @_;
	my %hash = ();

	for(@list) {
		my($name, @val) = @{ $_ };
		$hash{$name} = [ @val ];
	}
	return %hash;
}

BEGIN { $^W = $warning_save }

*/
#endif

