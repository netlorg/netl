
#include "includes.h"
#include "anti_sniff.h"
#ifdef SOLARIS
#include "dltest.h"
#endif

int send_raw_frame(HDEV fd, void *buff, int len, int flags);
HDEV open_net_intf(int value);
char *make_sixtysix(int *len);
u_short chksum(u_short *buf, int len);
unsigned long getaddr(char *addrStr);
void bzero(void *s, size_t n);
char *make_tcppack(int *, char *, char *, u_char, tcp_seq, tcp_seq);

/* 
   this will be changed to be a valid looking packet going to an invalid
   ether address - that way people who are pushing bpf or dlpi style 
   filters on their interfaces for optimization will still snag the 
   bogus packet - .mudge 
*/
void flood_local_net(HDEV fd, int packet_type, char *sourceIP, char *destIP){

  char *pkt, *pkt1, *pkt2, *pkt3;
  int ret, len, len1, len2, len3;
  int threewayflag = 0;
  char *defaultSourceIP = "192.168.1.10";
  char *defaultDestIP = "192.168.1.20";

  if (!sourceIP)
    sourceIP = defaultSourceIP;
  if (!destIP)
    destIP = defaultDestIP;

  switch(packet_type){
    case SIXTYSIX:
      pkt = make_sixtysix(&len);
      memset(pkt, 0x66, SIZE_FULL_PKT);
      break;
    case TCPSYN:
      pkt = make_tcppack(&len, sourceIP, destIP, TH_SYN, 12345, 0);
      break;
    case THREEWAY:
      pkt1 = make_tcppack(&len1, sourceIP, destIP, 
                          TH_SYN, 12345, 0);
      pkt2 = make_tcppack(&len2, destIP, sourceIP, 
                          TH_SYN|TH_ACK, 98765, 12346);
      pkt3 = make_tcppack(&len3, sourceIP, destIP, 
                          TH_ACK, 12346, 98766);
      threewayflag = 1;
      break;
    default:
      fprintf(stderr, "invalid arg for building packet!\n");
      exit(1);
      break;
  } 

  if (threewayflag){
    ret = send_raw_frame(fd, pkt1, len1, 0);
    if (ret == FALSE){
      fprintf(stderr, "problem sending raw frames!\n");
    }
    ret = send_raw_frame(fd, pkt2, len2, 0);
    if (ret == FALSE){
      fprintf(stderr, "problem sending raw frames!\n");
    }
    ret = send_raw_frame(fd, pkt3, len3, 0);
    if (ret == FALSE){
      fprintf(stderr, "problem sending raw frames!\n");
    }
  } else {
    ret = send_raw_frame(fd, pkt, len, 0);
    if (ret == FALSE){
      fprintf(stderr, "problem sending raw frames!\n");
    }
  }
}


#ifdef NIY
void watchdog(){
  watchdogFlag = TRUE;
  signal(SIGALARM, SIG_DFL);
}
#endif

char *make_sixtysix(int *len){
  char *pkt;
      
  pkt = (char *)malloc(SIZE_FULL_PKT); 
  if (!pkt){
    fprintf(stderr, "failed on malloc!!\n");
    exit(1);
  }

  /* note - this packet (well at least if size is 60bytes) turns off
     Net-Xray .mudge */
  memset(pkt, 0x66, SIZE_FULL_PKT);

  *len = SIZE_FULL_PKT;
  return(pkt);
}

char * 
make_tcppack(int *len, char *srcAddr, char *dstAddr, u_char flags, 
             tcp_seq sequence, tcp_seq acknowledgement){
  char *pkt;
  struct ether_header *eth;
  struct ip iph;
  struct tcphdr tcph, ltcph; 
  struct pseudo_header pheader;
  struct in_addr addr;

  pkt = malloc(SIZE_FULL_PKT);
  if (!pkt){
    fprintf(stderr, "failed on malloc!!\n");
    exit(1);
  }

  bzero(pkt, SIZE_FULL_PKT);

  /* ether section */
  eth = (struct ether_header *)pkt;
  memset(&eth->ether_dhost, 0x22, sizeof(struct ether_addr));
  memset(&eth->ether_shost, 0x66, sizeof(struct ether_addr));
  eth->ether_type = htons(ETHERTYPE_IP);
#ifdef DEBUG
  fprintf(stderr, "MADE ETHER\n");
#endif

  /* IP Section */
/*  iph = (struct ip*)((char *)(pkt + SIZE_ETHER_H));  */

#ifdef SOLARIS
  memset(&iph, 0x45, sizeof(u_char));
#else
  iph.ip_v = 4;
  iph.ip_hl = 5;
#endif

  iph.ip_len = htons(40);
  iph.ip_id = htons(0xcafe);
#if defined (SOLARIS)
  iph.ip_off = IP_DF;
#endif
#if defined (_OpenBSD_) || defined (_linux_)
  iph.ip_off = IP_DF & IP_OFFMASK;
#endif
  iph.ip_ttl = 60 ;
  iph.ip_p = IPPROTO_TCP;
  addr.s_addr = inet_addr(srcAddr);
  memcpy(&(iph.ip_src), &addr, sizeof(struct in_addr));
  addr.s_addr = inet_addr(dstAddr);
  memcpy(&(iph.ip_dst), &addr, sizeof(struct in_addr));

  iph.ip_sum = chksum((u_short *)&iph, SIZE_IP_H);

  memcpy((char *)(pkt + SIZE_ETHER_H), &iph, sizeof(struct ip)); 

#ifdef DEBUG
  fprintf(stderr, "MADE IP\n");
#endif
 
  /* TCP section */ 
/*  tcph = (struct tcphdr *)((char *)(pkt + SIZE_ETHER_H + SIZE_IP_H)); */
  bzero(&tcph, sizeof(struct tcphdr));
  tcph.th_sport = htons(23);
  tcph.th_dport = htons(23);

#ifdef OUT
  /* so lame with alignment problems... oh well here comes sleaze ;) */
  bzero(&ltcph, sizeof(struct tcphdr));
  memcpy(&ltcph, &tcph, SIZE_TCP_H);
  ltcph.th_flags = flags;
  ltcph.th_off = 5;
  ltcph.th_seq = htonl(sequence);
  ltcph.th_ack = htonl(acknowledgement);
  memcpy(tcph, &ltcph, SIZE_TCP_H);
#endif
  tcph.th_flags = flags;
  tcph.th_off = 5;
  tcph.th_seq = htonl(sequence);
  tcph.th_ack = htonl(acknowledgement);

#ifdef DEBUG
  fprintf(stderr, "'bout to do pseudo\n");
#endif
  /* pseudo header for TCP checksum */
  memcpy(&pheader.source_address, &(iph.ip_src), SIZE_IN_ADDR);
  memcpy(&pheader.dest_address, &(iph.ip_dst), SIZE_IN_ADDR);
  pheader.placeholder = 0;
  pheader.protocol = iph.ip_p;
  pheader.tcp_length = 20;
  memcpy(&pheader.tcp, &tcph, SIZE_TCP_H);

  tcph.th_sum = chksum((u_short *)&pheader, SIZE_PSEUDO_H);
  memcpy((char *)(pkt + SIZE_ETHER_H + SIZE_IP_H), &tcph, SIZE_TCP_H); 

#ifdef DEBUG
  fprintf(stderr, "MADE TCP\n");
#endif

  *len  = SIZE_FULL_PKT;
  return(pkt);
}

char *make_tcp_target(char *target, int *len){
  char *pkt;
  struct ether_header *eth;
  struct ip *iph;
  struct tcphdr *tcph, ltcph; 
  struct pseudo_header pheader;
  struct in_addr addr;

  pkt = malloc(SIZE_FULL_PKT);
  if (!pkt){                                
    fprintf(stderr, "failed on malloc!!\n");
    exit(1);
  }

  bzero(pkt, SIZE_FULL_PKT);

  /* ether section */
  eth = (struct ether_header *)pkt;
  memset(&eth->ether_dhost, 0x22, sizeof(struct ether_addr));
  memset(&eth->ether_shost, 0x66, sizeof(struct ether_addr));
  eth->ether_type = htons(ETHERTYPE_IP);
#ifdef DEBUG
  fprintf(stderr, "MADE ETHER\n");
#endif                    

  /* IP Section */   
  iph = (struct ip*)((char *)(pkt + SIZE_ETHER_H));          

#ifdef SOLARIS                                        
  memset(iph, 0x45, sizeof(u_char));
#else                                             
  iph->ip_v = 4;
  iph->ip_hl = 5;
#endif

  iph->ip_len = htons(40);
  iph->ip_id = htons(0xcafe);
#if definded (SOLARIS)
  iph->ip_off = IP_DF;
#endif
#if defined (_OpenBSD_) || defined (_linux_)
  iph->ip_off = IP_DF & IP_OFFMASK;
#endif
  iph->ip_ttl = 60 ;
  iph->ip_p = IPPROTO_TCP;
  addr.s_addr = inet_addr(target);
  memcpy(&iph->ip_src, &addr, sizeof(struct in_addr));
  addr.s_addr = inet_addr(target);
  memcpy(&iph->ip_dst, &addr, sizeof(struct in_addr));

  iph->ip_sum = chksum((u_short *)iph, SIZE_IP_H);
#ifdef DEBUG
  fprintf(stderr, "MADE IP\n");
#endif

  /* TCP section */
  tcph = (struct tcphdr *)((char *)(pkt + SIZE_ETHER_H + SIZE_IP_H));
  tcph->th_sport = htons(23);
  tcph->th_dport = htons(23);
  bzero(&ltcph, sizeof(struct tcphdr));
  memcpy(&ltcph, tcph, SIZE_TCP_H);
  ltcph.th_flags = TH_SYN;
  ltcph.th_off = 5;
  memcpy(tcph, &ltcph, SIZE_TCP_H);
#ifdef DEBUG
  fprintf(stderr, "'bout to do pseudo\n");
#endif           
  /* pseudo header for TCP checksum */
  memcpy(&pheader.source_address, &iph->ip_src, SIZE_IN_ADDR);
  memcpy(&pheader.dest_address, &iph->ip_dst, SIZE_IN_ADDR);
  pheader.placeholder = 0;
  pheader.protocol = iph->ip_p;
  pheader.tcp_length = 20;                        
  memcpy(&pheader.tcp, tcph, SIZE_TCP_H);            
    
  tcph->th_sum = chksum((u_short *)&pheader, SIZE_PSEUDO_H);
#ifdef DEBUG
  fprintf(stderr, "MADE TCP\n");
#endif

  *len  = SIZE_FULL_PKT;
  return(pkt);
}


u_short chksum(u_short *buf, int len){ /* from D.Reeds ipsend */
  u_long  sum = 0;
  int     nwords = len >> 1;

  for(; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum>>16) + (sum & 0xffff);
  sum += (sum >>16);
  return (~sum);
}

unsigned long getaddr(char *addrStr){

  struct in_addr addr;
  struct hostent *host;

  addr.s_addr = inet_addr(addrStr);

  if (addr.s_addr == -1){
    host = (struct hostent *)gethostbyname((char *)addrStr);
    if (!host){
      perror("util.c - gethostbyname");
      exit(1);
    }
    memcpy(&addr, host->h_addr, SIZE_IN_ADDR);
  }

  if (addr.s_addr == -1) {
    perror("inet_addr");
    exit(1);
  }
  return addr.s_addr;
}

