#include "includes.h"
#include "anti_sniff.h"

int main(){
  HDEV fd;
  struct ether_addr eaddr;
  int frameLen = 0, i;
  char *myPkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  int ret;

  fd = open_net_intf(-1);
  printf("open_net_intf returned %d\n", fd);

  if (getetheraddr(fd, &eaddr)){
    printf("getetheraddr returned true\n");
    printf("ether addr = %s\n", ether_ntoa(&eaddr));
  }
  else {
    printf("getetheraddr returned false\n");
  }
  
  while (1) {
    myPkt = (char *)recv_raw_frame(fd, &frameLen);
    printf("Frame Length: %d\n", frameLen);
    for (i = 0 ; i < frameLen ; i++ ) {
      printf("0x%02x ", (myPkt[i] & 0xff));
    }
    printf("\n");
    free(myPkt);
  }

/*
  ret = send_raw_frame(fd, (void *)myPkt, strlen(myPkt), 0);
  if (ret == TRUE)
    printf("send == TRUE\n");
  else
    printf("send == FALSE\n");
*/

  close(fd);
}
