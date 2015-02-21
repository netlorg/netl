#include "includes.h"
#include "anti_sniff.h"

#ifdef OUT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#endif

int isOurEchoPacket(int len, char *ret_data, int id);
void makeDeltatv(struct timeval *, struct timeval *, struct timeval *);
void bcopy(const void *s1, void *s2, size_t n);

#define SIZE_ECHO (sizeof(struct timeval) + sizeof(int))

#ifdef OUT
int main(int argc, char *argv[]){

  int avg=0;
  int SentPackets=0, RecvdPackets=0;

  if (argc != 2) {
     printf("bzzzt\n");
     exit(1);
  }

  avg = echotime(argv[1], 5, &SentPackets, &RecvdPackets);

  printf("Avg: %d\nSentPackets: %d\nRecvdPackets: %d\n", avg, SentPackets,
          RecvdPackets);
}

#endif

  
int echotime(char *target, int num_pkts, int *sent, int *recvd){

  int s, n, len;
  struct hostent *hp;
  struct sockaddr_in sin;
  struct timeval tv, tv2, delta_tv, timeout;
  int id, i, pkts_sent=0, pkts_recvd=0, ret, triptime=0;
  char *pkt_data, ret_data[SIZE_ECHO];
  fd_set inSet;
  int xyz;

  memset(&delta_tv, '\0', sizeof(struct timeval));

  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }

  if ((hp = gethostbyname(target)) == NULL){
    fprintf(stderr, "unknown host %s\n", target);
    exit(1);
  }

  /* set address of server on remote machine */
  sin.sin_family = AF_INET;
  sin.sin_port = htons(7);  /* echo */
  bcopy(hp->h_addr, &sin.sin_addr, hp->h_length);

  pkt_data = (char *)malloc(SIZE_ECHO);
  if (!pkt_data){
    perror("malloc");
    exit(1);
  }

#ifdef OUT 
  if (connect(s, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0){
    perror("connect");
  }
#endif

  for (i=0, id=1 ; i < num_pkts ; i++, id++){

    if (gettimeofday(&tv, NULL) == -1 ){
      perror("gettimeofday");
      exit(1);
    }

    memcpy(pkt_data, &tv, sizeof(struct timeval));
    memcpy(pkt_data + sizeof(struct timeval), &id, sizeof(int));

#ifdef OUT
    xyz = write(s, pkt_data, SIZE_ECHO);
    if (xyz < 0){
      perror("write");
      exit(1);
    }
#else
    xyz = sendto(s, pkt_data, SIZE_ECHO, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (xyz < 0){
      perror("sendto");
      exit(1);
    }
#endif
    pkts_sent++;

    FD_ZERO(&inSet);
    FD_SET(s, &inSet);

    len = sizeof(sin);
    ret =  select((s + 1), &inSet, NULL, NULL, &timeout);
    if (ret == -1){
      perror("select");
      exit(1);
    }
    if (ret == 0){
#ifdef DEBUG
      fprintf(stderr, "timed out on read...\n");
#endif
      continue;
    }

    n = recvfrom(s, ret_data, sizeof(ret_data), 0, (struct sockaddr *)&sin, &len);
    if (n < 0){
      perror("recvfrom");
      exit(1);
    }
    if (isOurEchoPacket(n, ret_data, id)){
      gettimeofday(&tv2, NULL);
      makeDeltatv((struct timeval *)ret_data,(struct timeval *)&tv2, &delta_tv);
      pkts_recvd++;
      triptime += delta_tv.tv_sec * 1000000 + delta_tv.tv_usec;
#ifdef DEBUG
      printf("delta seconds: %ld\ndelta usecs: %ld\n", delta_tv.tv_sec,
              delta_tv.tv_usec);
      printf("time latency: %ld\n", delta_tv.tv_sec * 1000000 + 
              delta_tv.tv_usec);
      printf("packets sent: %d\npackets received: %d\n", pkts_sent, pkts_recvd);
      printf("avg time so far: %d\n", triptime / pkts_recvd);
#endif
    }

    sleep(1);

  }
  /* would fill in result struct here */
  printf("packets sent: %d\npackets received: %d\n", pkts_sent, pkts_recvd);

  *sent = pkts_sent;
  *recvd = pkts_recvd;


  close(s);

  if (pkts_recvd)
    return(triptime / pkts_recvd);
  else
    return(0);

}

void makeDeltatv(struct timeval *result, struct timeval *curr_tv, 
                 struct timeval *d_tv){

  if (result->tv_sec > curr_tv->tv_sec){ /* should be impossible until 2036 */
#ifdef DEBUG
    printf("result seconds: %ld\ncurrent seconds: %ld\n", result->tv_sec, 
            curr_tv->tv_sec);
#endif
    return;
  }

  d_tv->tv_sec = curr_tv->tv_sec - result->tv_sec;  
  d_tv->tv_usec = curr_tv->tv_usec - result->tv_usec;
  if (d_tv->tv_usec < 0){
    d_tv->tv_sec--;
    d_tv->tv_usec += 1000000;
  }
  
}

int isOurEchoPacket(int len, char *ret_data, int id){
  struct echoPkt epkt;
 
  if (len < SIZE_ECHO)
    return 0;

  memcpy((char *)&epkt, ret_data, sizeof(struct echoPkt));

  if (epkt.id != id)
    return 0;

  return 1;
}
