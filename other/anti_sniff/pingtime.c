#include "includes.h"
#include "anti_sniff.h"

int tmin = 999999999;   /* minimum round trip time in millisec */
int tmax = 0;           /* maximum round trip time in millisec */
int tsum = 0;           /* sum of all times in millisec, for doing average */


/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define MAX_DUP_CHK     (8 * 128)

int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

int datalen = DEFDATALEN;

#define A(bit)          rcvd_tbl[(bit)>>3]      /* identify byte in array */
#define B(bit)          (1 << ((bit) & 0x07))   /* identify bit in byte */
#define CLR(bit)        (A(bit) &= (~B(bit)))

void finish();
void pinger(int s, int *, int ident);
int in_cksum(u_short *, int);
void pr_pack(char *buf, int cc, struct sockaddr_in *from, int *nreceived, 
             int ident); 
int summary(long nrepeats, long nreceived, int ntransmitted, int tmin,
            int tmax, int tsum); 


/* 
   hrmmm... we should probably pass in a flag so that pingtime() can be
   called to do regular latency deltas and also be called to do deltas 
   while flooding the network. This should make things easier for 
   the GUI writers...  .mudge
*/

int pingtime(struct sockaddr_in *target, int num_pkts, int *transd, int *recvd){
  int ntransmitted, nreceived;
  struct protoent *proto;
  int packlen, maxsize, maxsizelen;
  u_char *packet;
  int i;
  long nrepeats;
  int maxwait=MAXWAIT_DEFAULT;
  int s; /* socket fd */
  int ident;

  /* initialize locals */
  nrepeats = 0;
  ntransmitted = nreceived = 0;

/* 
   These are the globals that need to be reset... sigh - the original
   ping program from Mike Muus is really cool - but no points for
   coding style ;( Need to fix this eventually. .mudge
*/

  tmax = 0;           /* maximum round trip time in millisec */
  tsum = 0;           /* sum of all times in millisec, for doing average */
  tmin = 999999999;   /* minimum round trip time in millisec */

  num_pkts++;      /* we add 1 since we ignore the timing on the
                      first packet as it's skewed due to system
                      and net overhead for arp req/reply 
                      see pr_pack() .mudge */

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

  /* we should replace this with some random number to not give away our
     pid number in the icmp packet */
  /* ident = getpid() & 0xFFFF; */
#ifdef _OpenBSD_
  ident = (pid_t)(arc4random() & 0xFFFF);
#ifdef DEBUG
  printf("arc4random ident : %d\n", ident);
#endif
#else
  /* oooohhhhhh so LAME!!!! but quick... sigh */
  srand((int)time(NULL) & getpid());
  ident = rand() & 0xFFFF;
#ifdef DEBUG
  printf("lame ident : %d\n", ident);
#endif
#endif /* ELSE */


 /*
  * When trying to send large packets, you must increase the
  * size of both the send and receive buffers...
  */
  maxsizelen = sizeof maxsize;
  if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&maxsize, &maxsizelen) < 0){
    fprintf(stderr, "getsockopt");
    exit(1);
  }
  if (maxsize < packlen && setsockopt(s, SOL_SOCKET, SO_SNDBUF,
                                      (char *)&packlen,sizeof(maxsize)) < 0){
    fprintf(stderr, "setsockopt");
    exit(1);
  }
  
 /*
  * When pinging the broadcast address, you can get a lot of answers.
  * Doing something so evil is useful if you are trying to stress the
  * ethernet, or just want to fill the arp cache to get some stuff for
  * /etc/ethers.
  */
  (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&packlen, 
                   sizeof(packlen));

  for (i=0; i< num_pkts; i++) {
    struct sockaddr_in from;
    register int cc;
    int fromlen;
    fromlen = sizeof(from);

    (void)signal(SIGALRM, finish);
    sleep(1);
    pinger(s, &ntransmitted, ident);
    alarm(maxwait);
    if ((cc = recvfrom(s, (char *)packet, packlen, 0,
                       (struct sockaddr *)&from, &fromlen)) < 0) {
      if (errno == EINTR){
        alarm(0);
        continue;
      }
      perror("ping: recvfrom");
      alarm(0);
      continue;
    }
    else 
      pr_pack((char *)packet, cc, &from, &nreceived, ident); 

  }
  alarm(0);

  (void *)signal(SIGALRM, SIG_DFL);

  /* we sutract 1 from ntransmitted as we ignore the first packet
     in pr_pack since it's timing information is skewed due to arp
     requests and replies to match the ether to ip. see pr_pack() .mudge */
  *recvd = nreceived;
  *transd = (ntransmitted-1);
  return(summary(nrepeats, nreceived, (ntransmitted-1), tmin, tmax, tsum));

}


int summary(long nrepeats, long nreceived, int ntransmitted, int tmin,
            int tmax, int tsum) {

        int i=0;

        (void)putchar('\r');
        (void)fflush(stdout);

#ifdef DEBUG
        if (nrepeats)
                (void)printf("+%ld duplicates, ", nrepeats);
        if (ntransmitted) {
                if (nreceived > ntransmitted)
                        (void)printf("-- somebody's printing up packets!");
                else
                        (void)printf("%d%% packet loss",
                            (int) (((ntransmitted - nreceived) * 100) /
                            ntransmitted));
        }
        (void)putchar('\n');
#endif

      /*if (nreceived && timing) { */
        if (nreceived && 1) { /* always timing */
                /* Only display average to milliseconds */
                i = tsum / (nreceived + nrepeats);
#ifdef DEBUG
                (void)printf("round-trip min/avg/max = %d.%03d/%d.%03d/%d.%03d ms\n",
                    (int)(tmin / 1000), (int)(tmin % 1000),
                    (int)(i / 1000), (int)(i % 1000),
                    (int)(tmax / 1000), (int)(tmax % 1000));
#endif
        }
        return (i);
}

/*
 * finish --
 *      Print out statistics, and give up.
 */
void finish()
{
#ifdef DEBUG
       printf("timed out...\n");
#endif
}

/*
 * pinger --
 *      Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
void
pinger(int s, int *ntransmitted, int ident)
{
  register struct icmp *icp;
  register int cc;
  int i;
  u_char outpackhdr[MAXPACKET];
  u_char *outpack = outpackhdr+sizeof(struct ip);
  char *packet = outpack;
  struct timeval tv;
  struct tvi tvi;

  icp = (struct icmp *)outpack;
  icp->icmp_type = ICMP_ECHO;
  icp->icmp_code = 0;
  icp->icmp_cksum = 0;
  icp->icmp_seq = htons((*ntransmitted)++);
  icp->icmp_id = ident;                   /* ID */

  CLR(ntohs(icp->icmp_seq) % mx_dup_ck);

  (void)gettimeofday(&tv, (struct timezone *)NULL);
  tvi.tv_sec = htonl(tv.tv_sec);
  tvi.tv_usec = htonl(tv.tv_usec);
  memcpy((u_int *)&outpack[8], &tvi, sizeof tvi);

  cc = datalen + 8;                       /* skips ICMP portion */

  /* compute ICMP checksum here */
  icp->icmp_cksum = in_cksum((u_short *)icp, cc);

  i = sendto(s, (char *)packet, cc, 0, (struct sockaddr *)&whereto,
             sizeof(struct sockaddr));

  if (i < 0 || i != cc)  {
    if (i < 0)
      perror("ping: sendto");
  }
}


/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
int
in_cksum(addr, len)
        u_short *addr;
        int len;
{
        register int nleft = len;
        register u_short *w = addr;
        register int sum = 0;
        u_short answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

/*
 * pr_pack --
 *      Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void pr_pack(char *buf, int cc, struct sockaddr_in *from, int *nreceived, 
             int ident) { 
  register struct icmp *icp;
  struct ip *ip;
  struct timeval tv, tp;
  char *pkttime;
  int triptime = 0;
  int hlen;
  struct tvi tvi;

  (void)gettimeofday(&tv, (struct timezone *)NULL);

  /* Check the IP header */
  ip = (struct ip *)buf;
  hlen = ip->ip_hl << 2;
  if (cc < hlen + ICMP_MINLEN) 
    return;
  
  /* Now the ICMP part */
  cc -= hlen;
  icp = (struct icmp *)(buf + hlen);
  if (icp->icmp_type == ICMP_ECHOREPLY) {
    if (icp->icmp_id != ident)
      return;                 /* 'Twas not our ECHO */

    if (icp->icmp_seq == 0)
      return;    /* throw away the first one as there is time skew with
                    the inital arp request / reply */

    ++(*nreceived);

#ifndef icmp_data
    pkttime = (char *)&icp->icmp_ip;
#else
    pkttime = (char *)icp->icmp_data;
#endif
    memcpy(&tvi, pkttime, sizeof tvi);
    tp.tv_sec = ntohl(tvi.tv_sec);
    tp.tv_usec = ntohl(tvi.tv_usec);

    tv.tv_sec = tv.tv_sec - tp.tv_sec;
    tv.tv_usec = tv.tv_usec - tp.tv_usec;
    if (tv.tv_usec < 0) {
      tv.tv_sec--;
      tv.tv_usec += 1000000;
    }

    triptime = (tv.tv_sec * 1000000) + tv.tv_usec;
    tsum += triptime;
    if (triptime < tmin)
      tmin = triptime;
    if (triptime > tmax)
      tmax = triptime;

#ifdef DEBUG
    printf("seq # (%d) triptime - %d\n", icp->icmp_seq, triptime);
#endif

  }
}
