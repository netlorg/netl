#include "includes.h"
#include "anti_sniff.h"

void flood_local_net();
int pingtime(struct sockaddr_in *target, int num_pkts, int *, int *);

int main(int argc, char *argv[]){
  
  int avg1=0, avg2=0;
  extern struct sockaddr_in whereto;
  struct hostent *hp; 
  pid_t our_id;
  int num_pkts = 10;
  int num_trans = 0, num_recvd = 0;
 
  /* printf("argc = %d\n", argc); */

  if (argc < 2){
    fprintf(stderr, "program <target>\n");
    exit(1);
  }

  if (argc == 3)
    num_pkts = atoi(argv[2]); 

  memset(&whereto, 0, sizeof(struct sockaddr));
  whereto.sin_family = AF_INET;
  
  hp = gethostbyname(argv[1]);
  if (!hp){
    fprintf(stderr, "unknown host: %s", argv[1]);
    exit(1);
  }

  memcpy(&whereto.sin_addr, hp->h_addr, hp->h_length);
  
  avg1 = pingtime(&whereto, num_pkts, &num_trans, &num_recvd);
  
  our_id = fork();

  if (our_id == 0)
    flood_local_net(TCPSYN);
  else {
 
#ifdef DEBUG
    printf("going to start ping again while flooding\n");
#endif

    avg2 = pingtime(&whereto, num_pkts, &num_trans, &num_recvd);

  }

  if (our_id)
    if(kill(our_id, SIGKILL))
      printf("couldn not kill child!\n");

  printf("avg1 = %d avg2 = %d diff = %d\n", avg1, avg2, avg2 > avg1 ? (avg2 - avg1): (avg1 - avg2));

  return(1);  
}
