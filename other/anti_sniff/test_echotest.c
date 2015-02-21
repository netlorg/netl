#include "includes.h"
#include "anti_sniff.h"

int echotime(char *, int, int *, int *);

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

  return 1;
}

