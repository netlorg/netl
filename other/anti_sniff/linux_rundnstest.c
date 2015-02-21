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
  char *pkt;
  pid_t our_id;
  char promiscGuy[MAX_LEN];
  extern int errno;
  int shm_id;
  char *shm_addr;
  struct shmid_ds shm_desc;
 

  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "problem getting net interface\n");
    exit(1);
  }

  shm_id = shmget(100, sizeof(struct result), IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id == -1) {
    fprintf(stderr, "segment exists -- nuking...\n");
    /* we do the following to attach to what was already there and get the
       id back - we're going to attempt to nuke it and grab a new one */
    shm_id = shmget(100, sizeof(struct result), 0600);
    if (shmctl(shm_id, IPC_RMID, &shm_desc) == -1) {
      perror("shmctl");
      exit(1);
    }
    shm_id = shmget(100, sizeof(struct result), IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id == -1) {
      perror("shmget: ");
      exit(1);
    }
  }

  shm_addr = shmat(shm_id, NULL, 0);
  if (!shm_addr) { 
    perror("shmat: ");
    exit(1);
  }

  resPtr = (struct result *)shm_addr;

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

  /* detach shared mem */
  if (shmdt(shm_addr) == -1) {
    perror("shmdt:");
  }

  /* de-allocate shared segment */
  if (shmctl(shm_id, IPC_RMID, &shm_desc) == -1) {
    perror("shmctl:");
  }

  if (res->promisc){
/*    printf("res promisc!!\n"); */
    return(TRUE);
  } else {
/*    printf("no promisc\n"); */
    return(FALSE);
  }

}

