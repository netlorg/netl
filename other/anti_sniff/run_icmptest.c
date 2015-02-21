#include "includes.h"
#include "anti_sniff.h"

int pingtime(struct sockaddr_in *target, int num_pkts, int *sent, int *recvd);
void flood_local_net(HDEV fd, int packet_type, char *sourceIP, char *destIP);
HDEV open_net_intf(int);


int run_icmptimetest(int test, char *targetIP, int num_pkts, 
                     struct result *res){

  int avg1=0, avg2=0, pkts_sent=0, pkts_recvd=0;
  extern struct sockaddr_in whereto;
  struct hostent *hp;
  pid_t our_id;
  HDEV fd;

  res->checktype = ICMPTIMECHECK;

  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "problem getting net interface\n");
    exit(1);
  }

  memset(&whereto, 0, sizeof(struct sockaddr));
  whereto.sin_family = AF_INET;

  hp = gethostbyname(targetIP);
  if (!hp){
    res->status = FAILURE;
    res->checktype = ICMPTIMECHECK;
#ifdef SOLARIS25
    sprintf(res->errStr, "unknown host : %.100s", targetIP);
#else
    snprintf(res->errStr, MAX_LEN, "unknown host : %s", targetIP);
#endif
    return FALSE;
  }

  memcpy(&whereto.sin_addr, hp->h_addr, hp->h_length);

  avg1 = pingtime(&whereto, num_pkts, &pkts_sent, &pkts_recvd);
  
  res->time_avg1 = avg1;
  res->icmp_sent1 = pkts_sent;
  res->icmp_recv1 = pkts_recvd;

  our_id = fork();

  if (our_id == 0){
    for(;;){
      switch(test){
        case TCPSYN:
          flood_local_net(fd, TCPSYN, (char *)NULL, (char *)NULL);
          break;
        case SIXTYSIX:
          flood_local_net(fd, SIXTYSIX, (char *)NULL, (char *)NULL);
          break;
        case THREEWAY:
          flood_local_net(fd, THREEWAY, (char *)NULL, (char *)NULL);
          break;
        default:
          break;
      }
    }
  } else {

#ifdef DEBUG
    printf("going to start ping again while flooding\n");
#endif

    pkts_sent = 0 ; pkts_recvd = 0;
    avg2 = pingtime(&whereto, num_pkts, &pkts_sent, &pkts_recvd);
  
    res->time_avg2 = avg2;
    res->icmp_sent2 = pkts_sent;
    res->icmp_recv2 = pkts_recvd;

    res->TestType = test;

  }

  if (our_id)
    if(kill(our_id, SIGKILL))
      printf("couldn not kill child!\n");

  close(fd);

#ifdef DEBUG
  printf("avg1 = %d avg2 = %d diff = %d\n", avg1, avg2, avg2 > avg1 ? (avg2 - avg1): (avg1 - avg2));
#endif
  
  /* NIY make some assumptions and setup result struct  */

  return FALSE;
}

