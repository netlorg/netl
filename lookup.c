/*==============================================================================
| lookup.c
|   lookup tables for the netl/neta project
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
|  25 Feb 97  G. Ollis	.92 created module
|=============================================================================*/

#include "netl/global.h"	/* needed for ether.h */
#include "netl/ether.h"
#include "netl/lookup.h"

/*==============================================================================
| for config.c
==============================================================================*/

struct lookupitem icmptype[MAXICMPTYPE] = 
			      { {ICMP_ECHOREPLY,	"echoreply"},
				{ICMP_DEST_UNREACH,	"dest_unreach"},
				{ICMP_SOURCE_QUENCH,	"source_quench"},
				{ICMP_REDIRECT,		"redirect"},
				{ICMP_ECHO,		"echo"},
				{ICMP_TIME_EXCEEDED,	"time_exceeded"},
				{ICMP_PARAMETERPROB,	"parameterprob"},
				{ICMP_TIMESTAMP,	"timestamp"},
				{ICMP_TIMESTAMPREPLY,	"timestampreply"},
				{ICMP_INFO_REQUEST,	"info_request"},
				{ICMP_INFO_REPLY,	"info_reply"},
				{ICMP_ADDRESS,		"address"},
				{ICMP_ADDRESSREPLY,	"addressreply"}
			      };

struct lookupitem icmp6type[MAXICMP6TYPE] = {
				{ICMP6_DEST_UNREACH,	"dest_unreach"},
				{ICMP6_PACKET_TOO_BIG,	"packet_too_big"},
				{ICMP6_TIME_EXCEEDED,	"time_exceeded"},
				{ICMP6_PARAMETER_PROB,	"parameter_prob"},
				{ICMP6_ECHO_REQUEST,	"echo_request"},
				{ICMP6_ECHO_REPLY,	"echo_reply"},
				{ICMP6_GMQUERY,		"gmquery"},
				{ICMP6_GMQUERY,		"group_management_query"},
				{ICMP6_GMREPORT,	"gmreport"},
				{ICMP6_GMREPORT,	"group_management_report"},
				{ICMP6_GMREDUCTION,	"gmreduction"},
				{ICMP6_GMREDUCTION,	"group_management_reduction"},
				{ICMP6_ROUTER_SOLICITATION,
							"router_solicitation"},
				{ICMP6_ROUTER_ADVERTISEMENT,
							"router_advertisement"},
				{ICMP6_NEIGHBOR_SOLICITATION,
							"neighbor_solicitation"},
				{ICMP6_NETGHBOR_ADVERTISEMENT,
							"neighbor_advertisement"},
				{ICMP6_REDIRECT,	"redirect"}
			};

struct lookupitem icmpcode[MAXICMPCODE] =
			      { {ICMP_NET_UNREACH,	"net_unreach"},
				{ICMP_HOST_UNREACH,	"host_unreach"},
				{ICMP_PROT_UNREACH,	"port_unreach"},
				{ICMP_PORT_UNREACH,	"port_unreach"},
				{ICMP_FRAG_NEEDED,	"frag_needed"},
				{ICMP_SR_FAILED,	"sr_failed"},
				{ICMP_NET_UNKNOWN,	"net_unknown"},
				{ICMP_HOST_UNKNOWN,	"host_unknown"},
				{ICMP_HOST_ISOLATED,	"host_isolated"},
				{ICMP_NET_ANO,		"net_ano"},
				{ICMP_HOST_ANO,		"host_ano"},
				{ICMP_NET_UNR_TOS,	"net_unr_tos"},
				{ICMP_HOST_UNR_TOS,	"host_unr_tos"},
				{ICMP_PKT_FILTERED,	"pkt_filtered"},
				{ICMP_PREC_VIOLATION,	"prec_violation"},
				{ICMP_PREC_CUTOFF,	"prec_cutoff"},
				{ICMP_REDIR_NET,	"redir_net"},
				{ICMP_REDIR_HOST,	"redir_host"},
				{ICMP_REDIR_NETTOS,	"redir_nettos"},
				{ICMP_REDIR_HOSTTOS,	"redir_hosttos"},
				{ICMP_EXC_TTL,		"exc_ttl"},
				{ICMP_EXC_FRAGTIME,	"exc_fragtime"}
			      };

