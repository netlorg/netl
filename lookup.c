/*==============================================================================
| lookup.c
|   lookup tables for the netl/neta project
|
| this code is (c) 1997 Graham THE Ollis
|
|   this program is now written like it should be.
|   your free to modify and distribute this program as long as this header is
|   retained, source code is made *freely* available and you document your 
|   changes in some readable manner.
|
|  Date       Name	Revision
|  ---------  --------  --------
|  25 Feb 97  G. Ollis	.92 created module
|=============================================================================*/

#include "global.h"	/* needed for ether.h */
#include "ether.h"
#include "lookup.h"

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

struct lookupitem icmpcode[MAXICMPCODE] =
			      { {ICMP_NET_UNREACH,	"net_unreach"},
				{ICMP_HOST_UNREACH,	"host_unreach"},
				{ICMP_PROT_UNREACH,	"prot_unreach"},
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

