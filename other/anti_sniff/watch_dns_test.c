#include "includes.h"
#include "anti_sniff.h"

void * watchdns(HDEV, int *);
HDEV open_net_intf(int value);
int watch_dns_ptr(char *pkt, int len, char *ip_match);
void * watch_all_dns(HDEV fd, int *len);


int main(){

  HDEV fd;
  int len;
  char *pkt;

  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "problem getting net interface\n");
    exit(1);
  }

  for(;;){
    pkt = (char *)watch_all_dns(fd, &len);
    if (pkt && (len > 0)){
#ifdef NIY
      for (i=0 ; i < len ; i++){
        if ((i % 12) == 0 )
          printf("\n");
        printf("0x%02x ", pkt[i] & 0xff);
      }
#endif
      watch_dns_ptr(pkt, len, "128.89.89.89");
      printf("\n\n");
      free(pkt);
      len = 0;
    }
  }
}
