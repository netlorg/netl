#include "includes.h"
#include "anti_sniff.h"

HDEV open_net_intf(int value);
int arp_request(HDEV fd, char *, char *, struct result *);
void printResultStruct(struct result *);

int run_arptest(char *target, struct result *resStruct){

  HDEV fd;

  fd = open_net_intf(-1);
  /* add in error checking for open_net_intf */

  arp_request(fd, "ff:ff:ff:ff:ff:00", target, resStruct);
  return TRUE;
}

