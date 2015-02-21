#ifndef _ANTI_SNIFF_H
#define _ANTI_SNIFF_H

struct tvi {
        u_int   tv_sec;
        u_int   tv_usec;
};

#define DEFDATALEN      (64 - 8)                /* default data length */
#define MAXIPLEN        60
#define MAXICMPLEN      76
#define MAXPACKET       (65536 - 60 - 8)        /* max packet size */
#define MAXWAIT_DEFAULT	15

#define DNS_WAIT	10
#define ARP_WAIT	10

#define ETHERPINGWAIT 10


#define FALSE 0
#define TRUE  1

/* fuxin global from Mike Muss's ping */
struct sockaddr_in whereto;

int dns_done;

typedef int HDEV;

/* DEFINES */
#define SIZE_U_CHAR 1
#define SIZE_U_SHORT    2
#define SIZE_U_LONG     4
#define SIZE_IN_ADDR    4
#define SIZE_ETHER_H    14
#define SIZE_IP_H   20
#define SIZE_TCP_H  20
#define SIZE_UDP_H  8
#define SIZE_DNS_H  12
#define SIZE_FULL_PKT   54
#define SIZE_PSEUDO_H   32
#define SIZE_ICMP_H	28
#define MAXDLBUF        8192
#define MAX_LEN     256

#define ANTI_INTERFACE "ANTI_INTERFACE="

#if defined(SOLARIS)
#define DEVICENAME "le0"
#endif

#if defined(_OpenBSD_)
#define DEVICENAME "ep1"
#endif

#if defined(linux)
#define DEVICENAME "eth0"
#endif

enum { SIXTYSIX = 0, TCPSYN, THREEWAY };

struct pseudo_header{  /* For TCP header checksum */
  u_long source_address;
  u_long dest_address;
  u_char placeholder;
  u_char protocol;
  u_short tcp_length;
  struct tcphdr tcp;
};

struct result {
  u_short status;
#define SUCCESS 0
#define FAILURE 1
  u_short checktype;
#define ETHERPINGCHECK 0
#define ICMPTIMECHECK 1
#define DNSCHECK 2
#define ECHOTIMECHECK 3
#define ARPCHECK 4
#define NTETHERCHECK 5
  u_short TestType; /* TestTypes are currently: SIXTYSIX, TCPSYN, THREEWAY 
                       they are relevant for icmp time test and udp echo
                       time test */
  u_short promisc;
  char errStr[MAX_LEN];
  u_short time_avg1;
  u_short time_avg2;
  u_short icmp_sent1;
  u_short icmp_recv1;
  u_short icmp_sent2;
  u_short icmp_recv2;
  u_short echo_sent1;
  u_short echo_recv1;
  u_short echo_sent2;
  u_short echo_recv2;
  u_short exceeded_max_machines;
  char machines[MAX_LEN][MAX_LEN];
};

struct echoPkt {
  struct timeval timeValue;
  int id;
};

/* global for timeout */
/*
int watchdogFlag = FALSE;
*/

#endif
