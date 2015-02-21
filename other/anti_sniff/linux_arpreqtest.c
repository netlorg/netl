#include "includes.h"
#include "anti_sniff.h"

int getetheraddr(HDEV, struct ether_addr *);
int make_eth_addr(struct ether_addr *, char *);
int getipaddr(char *dev, struct in_addr *iaddr);
int make_ip(unsigned long *theip, char *thestring);
void * watch_all_arpresp(HDEV fd, int *len);
int match_arp_resp(char *pkt, int len, unsigned long matchIP, \
                   unsigned long our_ip);
int isUniqueMachineResult(struct result *r, char *machine);
int insertMachine(struct result *r, char *machine);
int send_raw_frame(HDEV fd, void *pkt, int len, int flags);


int arp_request(HDEV fd, char *ether_addr_arg, char *target_ip, struct result *res){
  struct ether_arp e_arp;
  struct ether_header eth;
  struct ether_addr target_ether, source_ether;
  unsigned long sourceIP, destIP;
  struct result *resPtr;
  char *defaultdevice = "eth0";
  int i;
  char *pkt1, *watchpkt;
  char *netdevice;
  pid_t our_id;
  int shm_id;
  char *shm_addr;
  struct shmid_ds shm_desc;
  
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
    perror("shmat:");
    exit(1);
  }

  resPtr = (struct result *)shm_addr;

  /* setup of final holding packet */
  pkt1 = (char *)malloc(MAXDLBUF);
  if (!pkt1){
    perror("malloc");
    exit(1);
  }
  memset(pkt1, '\0', MAXDLBUF);

  /* first make the ether packet */
  /* get the local machines ether addr as we do want responses - not 
     that it really matters as we are going to be sniffing for them */
  if (getetheraddr(fd, &source_ether) == FALSE){
    res->status = FAILURE;
    res->checktype = ARPCHECK;
    strncpy(res->errStr, "failed to get local ether addr", 32);
    return(FALSE);
  }

  /* make the target ether addr in the ether frame - to tickle the
     NT bug this should be ff:ff:ff:ff:ff:00 */
  if (make_eth_addr(&target_ether, ether_addr_arg) == FALSE){
    res->status = FAILURE;
    res->checktype = ARPCHECK;
    strncpy(res->errStr, "failed to make target ether addr", 33);
    return(FALSE);
  }

  netdevice = getenv(ANTI_INTERFACE);
  if (!netdevice)
    netdevice = defaultdevice;
  if (getipaddr(defaultdevice, (struct in_addr *)&sourceIP) == FALSE){
    res->status = FAILURE;
    res->checktype = ARPCHECK;
    strncpy(res->errStr, "failed to get source IP addr", 29);
    return(FALSE);
  }

  /* put them together and set the ether type to ETHERTYPE_ARP */
  memcpy(&eth.ether_dhost, &target_ether, sizeof(struct ether_addr));
  memcpy(&eth.ether_shost, &source_ether, sizeof(struct ether_addr));
  eth.ether_type = htons(ETHERTYPE_ARP);

  if (make_ip(&destIP, target_ip) == FALSE){
    res->status = FAILURE;
    res->checktype = ARPCHECK;
    strncpy(res->errStr, "failed to make target IP addr", 32);
    return(FALSE);
  }

  /* make the arp packet */
  e_arp.arp_hrd = htons(ARPHRD_ETHER);
  e_arp.arp_pro = htons(ETHERTYPE_IP);
  e_arp.arp_hln = 6;
  e_arp.arp_pln = 4;
  e_arp.arp_op = htons(ARPOP_REQUEST);

  memcpy(&e_arp.arp_sha, &source_ether, sizeof(struct ether_addr));
  memcpy(&e_arp.arp_spa, &sourceIP, 4);
  /* note -- this is usually ignored and filled in by the ARP reply
     we might want to have the ability to play with this in some bizarre
     cases but not right now */
  memset(&e_arp.arp_tha, '\0', sizeof(struct ether_addr));
  memcpy(&e_arp.arp_tpa, &destIP, 4);

  /* tie them all together */
  memcpy(pkt1, &eth, sizeof(struct ether_header));
  memcpy(pkt1+sizeof(struct ether_header), &e_arp, sizeof(struct ether_arp));

  /* send it */
  our_id = fork();
  if (our_id < 0){
    perror("fork");
    return FALSE;
  }

  if (our_id == 0){ /* CHILD */
    int len;
    for(;;){
      watchpkt = (char *)watch_all_arpresp(fd, &len);
      if (watchpkt && (len > 0)){
        if (match_arp_resp(watchpkt, len, destIP, sourceIP) == TRUE){
          /* check if it is a unique machine in the result struct */
          if (isUniqueMachineResult(resPtr, target_ip)){
             resPtr->promisc += 1;
             if ( insertMachine(resPtr, target_ip) == FALSE)
               resPtr->exceeded_max_machines = TRUE;
           }
        }
        len = 0;
      }
    } /* end parent */
  }
  else {
      for (i=0 ; i < ARP_WAIT / 2; i++){  
        send_raw_frame(fd, pkt1, sizeof(struct ether_header) + 
                       sizeof(struct ether_arp), 0);
        sleep(2);
      }
      kill(our_id, SIGTERM);
    }

    close(fd);

    memcpy(res, resPtr, sizeof(struct result));

    /* detach shared mem */
    if (shmdt(shm_addr) == -1) {
      perror("shmdt:");
    }

    /* de-allocate shared seg */
    if (shmctl(shm_id, IPC_RMID, &shm_desc) == -1) {
      perror("shmctl:");
    }

    res->status = SUCCESS;
    res->checktype = ARPCHECK;

    if (res->promisc)
      return TRUE;
    else
      return FALSE;
}
