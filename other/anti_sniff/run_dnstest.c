#include "includes.h"
#include "anti_sniff.h"

void * watchdns(HDEV, int *);
HDEV open_net_intf(int value);
int watch_dns_ptr(char *pkt, int len, char *ip_match);
void * watch_all_dns(HDEV fd, int *len);
void flood_local_net(HDEV fd, int packet_type, char *sourceIP, char *destIP);
void initResult(struct result *);
int getIPfromPkt(char *pkt, int len, char *holder);
int isUniqueMachineResult(struct result *r, char *machine);
int insertMachine(struct result *r, char *machine);


int run_dnstest(char *targetIP, struct result *res){

  HDEV fd;
  struct result *resPtr;
  int len, i;
#if defined(SOLARIS)
  int mfd;
#endif
  char *pkt;
  pid_t our_id;
  caddr_t area;
  char promiscGuy[MAX_LEN];
  extern int errno;
#ifdef _linux_
  char *linHolder;
#endif
 

  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "problem getting net interface\n");
    exit(1);
  }

#if defined(SOLARIS)
  mfd = open("/dev/zero", O_RDWR);
  if (mfd < 0){
    fprintf(stderr, "could not open /dev/zero\n");
    exit(1);
  }

  if (( area = mmap(0, sizeof(struct result), PROT_READ | PROT_WRITE, 
                    MAP_SHARED, mfd, 0)) == (caddr_t) -1){
    perror("mmap");
    fprintf(stderr, "could not map shared memory\n");
    close(fd) ; close(mfd);
    exit(1);
  }

  close(mfd); /* can close /dev/zero now that it's mapped */

#endif

#if defined (_OpenBSD_)
  if (( area = mmap(0, sizeof(struct result), PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_SHARED, -1, 0)) == (caddr_t) -1){
    perror("mmap");
    fprintf(stderr, "could not map shared memory\n");
    close(fd);
    exit(1);
  }
#endif

#if defined (_linux_)
  linHolder = malloc(getpagesize());
  if (!linHolder){
    perror("malloc");
    exit(1);
  }
  memset(linHolder, '\0', getpagesize());
  if (( area = mmap(linHolder, sizeof(struct result), PROT_READ | PROT_WRITE, 
                    MAP_SHARED|MAP_ANON, -1, 0)) == (void *) -1){
    perror("mmap");
    printf("area = %x\n", (char *)area);
    close(fd);
    exit(1);
  }
#endif

  resPtr = (struct result *)area;

  our_id = fork();
  if (our_id < 0){
    perror("fork");
    return FALSE;
  }

  if (our_id == 0){ /* CHILD */
 
    for(;;){
      pkt = (char *)watch_all_dns(fd, &len);
      if (pkt && (len > 0)){
        if (watch_dns_ptr(pkt, len, targetIP) == TRUE){
          getIPfromPkt(pkt + SIZE_ETHER_H, len, promiscGuy);
          if (isUniqueMachineResult(resPtr, promiscGuy)){
            resPtr->promisc += 1;
            if ( insertMachine(resPtr, promiscGuy) == FALSE)
              resPtr->exceeded_max_machines = TRUE;
          }
        }
    /*  free(pkt); */
        len = 0;
      }
    }
  } /* end child */
  else {
    for(i=0; i < DNS_WAIT / 2; i++){ 
      flood_local_net(fd, THREEWAY, targetIP, "192.168.2.100");
      sleep(2);
    }
    kill(our_id, SIGTERM);
  }

  close(fd);

  memcpy(res, resPtr, sizeof(struct result));

  res->checktype = DNSCHECK;

  if (res->promisc){
/*    printf("res promisc!!\n"); */
    return(TRUE);
  } else {
/*    printf("no promisc\n"); */
    return(FALSE);
  }

}

