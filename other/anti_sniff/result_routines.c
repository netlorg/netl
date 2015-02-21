#include "includes.h"
#include "anti_sniff.h"

void initResult(struct result *r){
  memset((char *)r, '\0', sizeof(struct result));
}

int isUniqueMachineResult(struct result *r, char *machine){
  int i;

  for (i=0 ; i < MAX_LEN ; i++){
    if (r->machines[i][0] == '\0')
      return TRUE;
    if (strcmp(r->machines[i], machine) == 0)
      return FALSE;
  }

  return FALSE;
}

int insertMachine(struct result *r, char *machine){
  int i;

  for (i=0 ; i < MAX_LEN ; i++){
    if (r->machines[i][0] == '\0'){
      strncpy(r->machines[i], machine, MAX_LEN);
      return TRUE;
    }
  }
  return FALSE;
}

void printResultStruct(struct result *r){
  int i;

  printf("[*]--Results of test--[*]\n");
  printf("     status       : %s", (!r->status) ? "SUCCESS\n" : "FAILURE\n");
  printf("     checktype    : ");
  switch(r->checktype){
    case ETHERPINGCHECK:
      printf("ETHERPINGCHECK\n");
      break;
    case ICMPTIMECHECK:
      printf("ICMPTIMECHECK\n");
      break;
    case DNSCHECK:
      printf("DNSCHECK\n");
      break;
    case ARPCHECK:
      printf("ARPCHECK\n");
      break;
    case ECHOTIMECHECK:
      printf("ECHOTIMECHECK\n");
      break;
    case NTETHERCHECK:
      printf("NTETHERCHECK\n");
      break;
    default:
      printf("UNKNOWN\n");
      break;
  } 
  printf("     icmpTestType : ");
  if ((r->checktype != ICMPTIMECHECK) && (r->checktype != ECHOTIMECHECK))
    printf("---\n");
  else{
    switch(r->TestType){
      case SIXTYSIX:
        printf("SIXTYSIX\n");
        break;
      case TCPSYN:
        printf("TCPSYN\n");
        break;
      case THREEWAY:
        printf("THREEWAY\n");
        break;
      default:
        printf("UNKNOWN\n");
        break;
    }
  }
  printf("     promisc cnt  : %d\n", r->promisc);
  printf("     errStr       : %s\n", r->errStr);
  printf("     avg1         : %d\n", r->time_avg1);
  printf("     avg2         : %d\n", r->time_avg2);
  printf("     sent1        : %d\n", r->icmp_sent1);
  printf("     recv1        : %d\n", r->icmp_recv1);
  printf("     sent2        : %d\n", r->icmp_sent2);
  printf("     recv2        : %d\n", r->icmp_recv2);
  printf("     overflow     : %s", (r->exceeded_max_machines) ? "YES\n" : 
                              "NO\n");
  
  printf("    machines list:\n");
  for (i=0 ; i < MAX_LEN; i++){
    if (r->machines[i][0] == '\0')
      break;
    printf("      %s\n", r->machines[i]);
  }

}

/* massageResult tweaks and makes guestimates about some of the information
   in the result struct */
void massageResult(struct result *r, char *machine){

  switch(r->checktype){
    case ETHERPINGCHECK:
      break;
    case ICMPTIMECHECK:
      /* if ICMP is blocked or the machine does not respond to it
         then lets bail right here */
      if (r->icmp_recv1 == 0)
        return;

      /* packet loss is interesting to us - the following will attempt to
         buttress up the avg times to show packet loss */
      if (r->icmp_recv1 < r->icmp_sent1){
        r->time_avg1 += (r->icmp_sent1 - r->icmp_recv1) * 
                        ((r->time_avg1 / r->icmp_recv1) * 1000);
      }
      if (r->icmp_recv2 < r->icmp_sent2){
        r->time_avg2 += (r->icmp_sent2 - r->icmp_recv2) * 
                        ((r->time_avg2 / r->icmp_recv2) * 1000);
      }
      
      /* if the second average is 3 times the first one we are pretty
         sure the machine is in promisc mode and running a horribly
         non-optimized sniffer */
      if (r->time_avg2 >= (r->time_avg1 * 3)){ 
        r->promisc = 1;
        insertMachine(r, machine);
      } 
      break;
    case DNSCHECK:
      break;
    case ECHOTIMECHECK:
      /* if UDP is blocked or the machine does not have echo running
         then lets bail right here */
      if (r->echo_recv1 == 0)
        return;

      /* packet loss is interesting to us - the following will attempt to
         buttress up the avg times to show packet loss */
      if (r->echo_recv1 < r->echo_sent1){
        r->time_avg1 += (r->echo_sent1 - r->echo_recv1) *
                        ((r->time_avg1 / r->echo_recv1) * 1000);
      }
      if (r->echo_recv2 < r->echo_sent2){
        r->time_avg2 += (r->echo_sent2 - r->echo_recv2) *
                        ((r->time_avg2 / r->echo_recv2) * 1000);           
      }                                          

      /* if the second average is 3 times the first one we are pretty
         sure the machine is in promisc mode and running a horribly
         non-optimized sniffer */
      if (r->time_avg2 >= (r->time_avg1 * 3)){
        r->promisc = 1;
        insertMachine(r, machine);
      }
      break;
  }
}
