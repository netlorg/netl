#include "includes.h"
#include "anti_sniff.h"

void *make_icmp_echo(char *eth_dst, char *eth_src, char *target_ip, char *src_ip, int ident, int *len);
void ether_finished();
int etherping(HDEV fd, char *ether_addr, char *target_ip, struct result *);
int getetheraddr(HDEV fd, struct ether_addr *eaddr);
int send_raw_frame(HDEV fd, void *buff, int len, int flags);
int match_packet(char *packet, int cc, struct sockaddr_in *from, int ident);
u_short chksum(u_short *buf, int len);
int getipaddr(char *dev, struct in_addr *iaddr);
int getIPfromPkt(char *pkt, int len, char *holder);
int isUniqueMachineResult(struct result *, char *);
int insertMachine(struct result *, char *);
char *ether_ntoa (struct ether_addr *e);
struct ether_addr *ether_aton (char *s);


int etherping_done=0;
static jmp_buf env_alrm;

void ether_finished(){
#ifdef DEBUG
  printf("timed out...\n");
#endif
  etherping_done = 1;
  signal(SIGALRM, SIG_DFL); 
  alarm(0);
  longjmp(env_alrm, 1);
}

/* NOTE! This particular test will only work against certain messed up 
   kernels (ie Linux) and has to be done on the local network (ie it
   can't go through routers since this is relying upon manipulation of
   the ether frame. As such, we should do some checks on the target ip
   to make sure it is on the local segment .mudge */

/* returns TRUE if machine is in promiscuous... FALSE otherwise */
int etherping(HDEV fd, char *ether_addr, char *target_ip, struct result *res){
  
  int s; /* socket */
  struct protoent *proto;
  int fromlen, ident, len, packlen, cc;
  struct sockaddr_in from;
  u_char *packet;
  char *icmp_pack;
  char ether_src[18];
  struct ether_addr e_src;
  struct in_addr iaddr;
  char promiscGuy[MAX_LEN];

  fromlen = sizeof(from);

  if (!(proto = getprotobyname("icmp"))){
    perror("unknown protocol icmp");
    exit(1);
  }

  if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0){
    perror("socket");
    exit(1);
  }

  packlen = DEFDATALEN + MAXIPLEN + MAXICMPLEN;

  if (!(packet = (u_char *)malloc((u_int)packlen))){
    fprintf(stderr, "malloc");
    exit(1);
  }

  (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&packlen,
                   sizeof(packlen));

#ifdef _OpenBSD_
  ident = (pid_t)(arc4random() & 0xFFFF);             
#ifdef DEBUG   
  printf("arc4random ident : 0x%x\n", ident);             
#endif
#else                                                
  /* oooohhhhhh so LAME!!!! but quick... sigh */                         
  srand((int)time(NULL) & getpid());                                 
  ident = rand() & 0xFFFF;                                            
#ifdef DEBUG                    
  printf("lame ident : 0x%x\n", ident);
#endif
#endif /* ELSE */

  /* make and send raw ICMP echo request packet with bogus dest ether addr */
  getetheraddr(fd, &e_src);
#ifdef SOLARIS25
  sprintf(ether_src, "%.18s", ether_ntoa(&e_src));
#else
  snprintf(ether_src, sizeof(ether_src), "%s", ether_ntoa(&e_src));
#endif
  getipaddr(DEVICENAME, &iaddr);
  icmp_pack = (char *)make_icmp_echo(ether_addr, ether_src, target_ip, inet_ntoa(iaddr), ident, &len);
/*   send_raw_frame(fd, icmp_pack, len, 0);  */

  /* listen for response */
  (void)signal(SIGALRM, ether_finished);
  
/* new */
  if (setjmp(env_alrm) != 0){
    alarm(0);
    close(s);
    free(packet);
    if (res->promisc)
      return(TRUE);
    else
      return(FALSE);
  } 

  alarm(ETHERPINGWAIT);
  for(;;){
    send_raw_frame(fd, icmp_pack, len, 0);  
    if ((cc = recvfrom(s, (char *)packet, packlen, 0, 
         (struct sockaddr *)&from, &fromlen)) < 0 ) {
      if (errno == EINTR){
        alarm(0);
        close(s);
        free(packet);
        if (res->promisc)
          return(TRUE);
        else
          return(FALSE);
      }
    } else {
      if (match_packet((char *)packet, cc, &from, ident) == TRUE){
        getIPfromPkt(packet, cc, promiscGuy);
        if (isUniqueMachineResult(res, promiscGuy)){
          res->promisc += 1;
          if (res->promisc >= MAX_LEN)
            res->exceeded_max_machines = 1;
          else 
            insertMachine(res, promiscGuy);
        }
      }
    }
    if (etherping_done)
      break;
  }
  alarm(0);
  if (res->promisc)
    return(TRUE);
  else
    return(FALSE);
}

int match_packet(char *packet, int cc, struct sockaddr_in *from, int ident){
  struct icmp *icp;
  struct ip *ip;
  int hlen;

  /* Check the IP header */
  ip = (struct ip *)packet;
  hlen = ip->ip_hl << 2;
  if (cc < hlen + ICMP_MINLEN)
    return(FALSE);
  
  /* Now the ICMP part */
  /* note - eventually we need to check the IP address that it came from...
     a malicious ;) person could just watch our ident numbers and make it
     look like every machine on the net is promisc. */
  cc -= hlen;
  icp = (struct icmp *)(packet + hlen);
  if (icp->icmp_type == ICMP_ECHOREPLY) {
    if (ntohs(icp->icmp_id) != ident)
      return(FALSE);           /* 'Twas not our ECHO */
    else
      return(TRUE);
  } else
    return(FALSE);
}


void *make_icmp_echo(char *eth_dst, char *eth_src, char *target_ip, char *src_ip, int ident, int *len){
  struct ip iph;
  char *pkt;
  struct ether_header eth_h;
  struct icmp *icp;
  struct in_addr addr;
  
  pkt = (char *)malloc(SIZE_ETHER_H + SIZE_IP_H + SIZE_ICMP_H);
  if (!pkt){
    perror("malloc");
    exit(1);
  }

  /* ETHER SECTION */
  
  memcpy(&eth_h.ether_dhost, (char *)ether_aton(eth_dst), sizeof(struct ether_addr));
  memcpy(&eth_h.ether_shost, (char *)ether_aton(eth_src), sizeof(struct ether_addr));

  eth_h.ether_type = htons(ETHERTYPE_IP);
  memcpy(pkt, &eth_h, SIZE_ETHER_H);

  /* IP Section */

  iph.ip_v = 4;
  iph.ip_hl = 5;

  iph.ip_len = htons(SIZE_IP_H + SIZE_ICMP_H);
  iph.ip_id = htons(0xcafe);
#if defined(SOLARIS)
  iph.ip_off = IP_DF;
#endif
#if defined(_OpenBSD_) || defined (_linux_)
  iph.ip_off = IP_DF & IP_OFFMASK;
#endif
  iph.ip_ttl = 60 ;
  iph.ip_p = IPPROTO_ICMP;
  /* XXX replace this with the local machine IP */
  /* addr.s_addr = inet_addr("192.168.1.5"); */
  addr.s_addr = inet_addr(src_ip);
  memcpy(&(iph.ip_src), &addr, sizeof(struct in_addr));
  addr.s_addr = inet_addr(target_ip);
  memcpy(&(iph.ip_dst), &addr, sizeof(struct in_addr));

  iph.ip_sum = chksum((u_short *)&iph, SIZE_IP_H);
  memcpy(((char *)pkt + SIZE_ETHER_H), &iph, sizeof(struct ip)); 
#ifdef DEBUG
  fprintf(stderr, "MADE IP\n");
#endif

  /* ICMP */
  icp = (struct icmp *)((char *)(pkt + SIZE_ETHER_H + SIZE_IP_H)); 
  icp->icmp_type = ICMP_ECHO;
  icp->icmp_code = 0;
  icp->icmp_cksum = 0;
  icp->icmp_seq = htons(1);
  icp->icmp_id = htons(ident);

  /* CLR(ntohs(icp->icmp_seq) % ( 8 * 128)); */
  icp->icmp_seq = htons(77);

  icp->icmp_cksum = chksum((u_short *)icp, SIZE_ICMP_H);

  *len = SIZE_ETHER_H + SIZE_IP_H + SIZE_ICMP_H;
  return(pkt);
} 

