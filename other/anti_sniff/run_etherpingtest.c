#include "includes.h"
#include "anti_sniff.h"


void initResult(struct result *);
HDEV open_net_intf(int value);
int etherping(HDEV fd, char *ether_addr, char *target_ip, struct result *);
struct ether_addr *ether_aton (char *s);

int run_etherpingtest(char *targetIP, char *etherADDR, 
                      struct result *resultStruct){

  HDEV fd;
  int i;

  resultStruct->checktype = ETHERPINGCHECK;
 
  fd = open_net_intf(-1);
  if (fd < 0){
    fprintf(stderr, "failed to open network interface\n");
    exit(1);
  }

  if (ether_aton(etherADDR) == NULL){
    resultStruct->status = FAILURE;
    strncpy(resultStruct->errStr, "invalid ether address", MAX_LEN);
    close(fd);
    return FALSE;
  }

  if (inet_addr(targetIP) == -1){
    resultStruct->status = FAILURE;
    strncpy(resultStruct->errStr, "invalid IP address", MAX_LEN);
    close(fd);
    return FALSE;
  }

  for (i=0 ; i < 5 ; i++){
    if (etherping(fd, etherADDR, targetIP, resultStruct) == TRUE){
      resultStruct->status = SUCCESS;
      /* the list of promisc folks and promisc count is set in etherping */
      close(fd);
      return TRUE;
    } 
  }
  close(fd);
  return FALSE;
    
}
