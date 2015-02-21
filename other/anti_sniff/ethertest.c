#include "includes.h"
#include "anti_sniff.h"

HDEV open_net_intf(int);
int etherping(HDEV, char *, char *, struct result *);
int getopt(int argc, char * const *argv, const char *optstring);
void usage(char *prog);
#ifdef _linux_
extern struct ether_addr *ether_aton __P ((__const char *__asc));
#endif


/* stub tester */
int main(int argc, char *argv[])
{
  struct result res;
  HDEV fd;
  int i, c, eflag = 0, iflag = 0;
  char *ether_ptr = NULL, *ip_ptr = NULL;
  extern char *optarg;

  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "failed to open network interface\n");
    exit(1);
  }

  while ((c = getopt(argc, argv, "e:i:")) != EOF){
    switch (c) {
      case 'e':
        ether_ptr = optarg;
        eflag++;
        break;
      case 'i':
        ip_ptr = optarg;
        iflag++;
        break;
      default:
        usage(argv[0]);
        break;
    }
  }
  if (!eflag || !iflag)
    usage(argv[0]);

  if (ether_aton(ether_ptr) == NULL){
    printf("invalid ether addr\n");
    exit(1);
  }
  if (inet_addr(ip_ptr) == -1){
    printf("invalid ip addr\n");
    exit(1);
  }

  for (i=0 ; i < 5 ; i++){
    if (etherping(fd, ether_ptr, ip_ptr, &res) == TRUE) 
      printf("PROMISC\n");
    else
      printf("seems normal\n");
  }
  return(0);
}

void usage(char *prog){
  printf("usage: %s -e etheraddress -i ipaddress\n", prog);
  exit(1);
}
