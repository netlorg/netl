#include "includes.h"
#include "anti_sniff.h"

HDEV open_net_intf(int value);
int arp_request(HDEV fd, char *, char *, struct result *);
void printResultStruct(struct result *);

int main(int argc, char *argv[]){
  HDEV fd;
  struct result Res;

  if (argc != 2) {
     printf("usage : %s target_IP\n", argv[0]);
     exit(1);
  }

  fd = open_net_intf(-1);
  arp_request(fd, "ff:ff:ff:ff:ff:00", argv[1], &Res);
  printResultStruct(&Res);
  exit(1);
}

