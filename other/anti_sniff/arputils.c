#include "includes.h"
#include "anti_sniff.h"

int 
match_arp_resp(char *pkt, int len, unsigned long matchIP, 
                   unsigned long our_ip){

  struct ether_arp da_arp;

  if (len < sizeof(struct ether_header) + sizeof(struct ether_arp))
    return FALSE;

  memcpy((char *)&da_arp, (char *)pkt + sizeof(struct ether_header), 
         sizeof(struct ether_arp));

  if (memcmp(&(da_arp.arp_tpa), &our_ip, 4) != 0)
    return FALSE;

  if (memcmp(&(da_arp.arp_spa), &matchIP, 4) == 0)
    return TRUE;
  else
    return FALSE;
}

