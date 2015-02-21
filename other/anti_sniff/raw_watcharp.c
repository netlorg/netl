#include "includes.h"
#include "anti_sniff.h"

void *recv_raw_frame(HDEV fd, int *len);

void * watch_all_arpresp(HDEV fd, int *len){

  int length=0;
  void *pkt;
  struct ether_header eth;
  struct ether_arp earp ;

  for (;;){
    pkt = (char *)recv_raw_frame(fd, &length);

    if (length == SIZE_ETHER_H + sizeof(struct ether_arp)) {
      /* check to see if it's an arp packet */
      memcpy((char *)&eth, pkt, SIZE_ETHER_H);
      if (ntohs(eth.ether_type) != ETHERTYPE_ARP)
        continue;

      /* check to see if it's an arp request - if so break, if not
         continue */
      memcpy((char *)&earp, (char *)(pkt + SIZE_ETHER_H), 
              sizeof(struct ether_arp));
      if (earp.ea_hdr.ar_op != ARPOP_REPLY){
        free(pkt);
        continue; 
      }
      else
        break;
    }  
  }

  if (pkt){
    *len = length;
    return(pkt);
  } else {
    *len = -1;
    return(NULL);
  }
}


