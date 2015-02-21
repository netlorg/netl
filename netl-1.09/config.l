%{

/*==============================================================================
| config.l
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
|=============================================================================*/

#include <unistd.h>
#include <string.h>

#include "netl/global.h"
#include "netl/ether.h"
#include "netl/ip.h"

#include "netl/io.h"
#include "netl/action.h"
#include "netl/filter.h"
#include "netl/config.h"
#include "config.tab.h"

int line_number = 1;
int in_quote = 0;

#define YY_NO_UNPUT

/*		fprintf(stderr, "token(%s,%s)\n", nm, yytext);	\
*/

#define cpy(nm) yylval.x.s = allocate(yyleng+1);		\
		yylval.x.i = -1;				\
		yylval.x.h = -1;				\
		strcpy(yylval.x.s, yytext)

#define cpy2(nm,num) 						\
		yylval.x.s = allocate(yyleng+1);		\
		yylval.x.i = -1;				\
		yylval.x.h = -1;				\
		yylval.x.code = num;				\
		strcpy(yylval.x.s, yytext)

#define cpy3()							\
		yylval.x.i = -1;				\
		yylval.x.h = -1;				\
		yylval.x.code = -1

static int paran_depth = 0, brace_depth = 0;

%}

letter			[a-zA-Z]
digit			[0-9]
alphanum		[a-zA-Z0-9\._]
hd			[A-Fa-f0-9]

%s QUOTED STRING

%%

\n			line_number++;	cpy3(); if(paran_depth == 0) return NL;
[ \t]+			/* ignore white space */
"#".*\n			cpy3(); 	line_number++; if(paran_depth == 0 && brace_depth == 0) return NL; /* skip comments */

<INITIAL>\"		{ in_quote = 1; BEGIN QUOTED; }
<QUOTED>\"		{ in_quote = 0; BEGIN 0; }
<QUOTED>[^\"]+		{ 
				cpy("CON_STR");
				return CON_STR;
			}

<INITIAL>"("		paran_depth++;	cpy3(); return '(';
<INITIAL>")"		paran_depth--;	cpy3(); return ')';
<INITIAL>"{"		brace_depth++;	cpy3(); return '{';
<INITIAL>"}"		brace_depth--;	cpy3(); return '}';
<INITIAL>";"		cpy3(); return NL;

<INITIAL>"if"		cpy3(); return KEY_IF;
<INITIAL>"and"		cpy3(); return KEY_AND;
<INITIAL>"&&"		cpy3(); return KEY_AND;
<INITIAL>"or"		cpy3(); return KEY_OR;
<INITIAL>"||"		cpy3(); return KEY_OR;

<INITIAL>"device"	cpy3();	return RULE_DEVICE;
<INITIAL>"detect"	cpy3();	return RULE_DETECT;
<INITIAL>"alias"	cpy3();	return RULE_ALIAS;
<INITIAL>"listen"	cpy3();	return RULE_LISTEN;
<INITIAL>"dir lib"	cpy3(); return RULE_DIR_LIB;
<INITIAL>"dir dump"	cpy3(); return RULE_DIR_DUMP;

<INITIAL>"ignore"	cpy2("RULE_T", ACTION_IGNORE);	return RULE_T;
<INITIAL>"log"		cpy2("RULE_T", ACTION_LOG);	return RULE_T;
<INITIAL>"dump"		cpy2("RULE_T", ACTION_DUMP);	return RULE_T;
<INITIAL>"dl"		cpy2("RULE_T", ACTION_DL);	return RULE_T;
<INITIAL>"null"		cpy2("RULE_T", ACTION_NULL);	return RULE_T;
<INITIAL>"pipe"		cpy2("RULE_T", ACTION_PIPE);	return RULE_T;
<INITIAL>"@"{alphanum}+	cpy2("RULE_T", ACTION_USER);	return RULE_T;


<INITIAL>"raw"		cpy2("PROT", PROT_RAW);		return PROT;

<INITIAL>"tcp"		cpy2("PROT", PROT_TCP);		return PROT;
<INITIAL>"icmp"		cpy2("PROT", PROT_ICMP);	return PROT;
<INITIAL>"ignp"		cpy2("PROT", PROT_IGNP);	return PROT;
<INITIAL>"udp"		cpy2("PROT", PROT_UDP);		return PROT;
<INITIAL>"ip"		cpy2("PROT", PROT_IP);		return PROT;

<INITIAL>"tcp4"		cpy2("PROT", PROT_TCP4);	return PROT;
<INITIAL>"icmp4"	cpy2("PROT", PROT_ICMP4);	return PROT;
<INITIAL>"ignp4"	cpy2("PROT", PROT_IGNP4);	return PROT;
<INITIAL>"udp4"		cpy2("PROT", PROT_UDP4);	return PROT;
<INITIAL>"ip4"		cpy2("PROT", PROT_IP4);		return PROT;

<INITIAL>"tcp6"		cpy2("PROT", PROT_TCP6);	return PROT;
<INITIAL>"icmp6"	cpy2("PROT", PROT_ICMP6);	return PROT;
<INITIAL>"ignp6"	cpy2("PROT", PROT_IGNP6);	return PROT;
<INITIAL>"udp6"		cpy2("PROT", PROT_UDP6);	return PROT;
<INITIAL>"ip6"		cpy2("PROT", PROT_IP6);		return PROT;

<INITIAL>"&"{alphanum}+	cpy2("PROT", PROT_USER);	return PROT;

<INITIAL>"name="	cpy3();	return FLD_NAME;
<INITIAL>"flag="	cpy3();	return FLD_FLAG;
<INITIAL>"dstport="	cpy3();	return FLD_DSTPORT;
<INITIAL>"srcport="	cpy3();	return FLD_SRCPORT;
<INITIAL>"dstip="	cpy3();	return FLD_DSTIP;
<INITIAL>"srcip="	cpy3();	return FLD_SRCIP;
<INITIAL>"dsthw="	cpy3();	return FLD_DSTHW;
<INITIAL>"srchw="	cpy3();	return FLD_SRCHW;
<INITIAL>"type="	cpy3();	return FLD_TYPE;
<INITIAL>"type6="	cpy3(); return FLD_TYPE6;
<INITIAL>"code="	cpy3();	return FLD_CODE;

<INITIAL>"urg"		cpy2("FLG", FLG_URG);	return FLG;
<INITIAL>"ack"		cpy2("FLG", FLG_ACK);	return FLG;
<INITIAL>"psh"		cpy2("FLG", FLG_PSH);	return FLG;
<INITIAL>"rst"		cpy2("FLG", FLG_RST);	return FLG;
<INITIAL>"syn"		cpy2("FLG", FLG_SYN);	return FLG;
<INITIAL>"fin"		cpy2("FLG", FLG_FIN);	return FLG;
<INITIAL>"all"		cpy2("FLG", FLG_ALL);	return FLG;

<INITIAL>{digit}+	{
				cpy("CON_INT");
				yylval.x.i = atoi(yytext);
				yylval.x.h = ahextoi(yytext);
				return CON_INT;
			}

<INITIAL>{hd}+		{
				cpy("CON_INT(hd)");
				yylval.x.h = ahextoi(yytext);
				return CON_INT;		/* fix me! */
			}

"!"			{
				cpy3();
				return yytext[0];
			}

<INITIAL>{alphanum}+	{
				cpy("CON_STR");
				return CON_STR;
			}

.			{
				cpy3();
				return yytext[0];
			}

%%

