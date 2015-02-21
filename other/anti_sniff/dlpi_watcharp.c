#include "includes.h"
#include "anti_sniff.h"

void *recv_raw_frame(HDEV fd, int *len);
void dlunbindreq(int fd);
void dlokack(int fd, char *buf);
void dlbindack(int fd, char *buf);
void dlbindreq(int fd, u_long, u_long, u_long, u_long, u_long);


void * watch_all_arpresp(HDEV fd, int *len){

  int length=0;
  void *pkt;
  struct ether_arp earp ;
  char buf[256];

  dlunbindreq(fd);
  dlokack(fd, buf);

  dlbindreq(fd, ETHERTYPE_ARP, 0, DL_CLDLS, 0, 0);
  dlbindack(fd, buf);

  for (;;){
    pkt = (char *)recv_raw_frame(fd, &length);
    /* make sure it's at least big enough and not a random ether frame
       with type 0x0806 */
    if (length >= SIZE_ETHER_H + sizeof(struct ether_arp)) {
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

  dlunbindreq(fd);
  dlokack(fd, buf);

  dlbindreq(fd, ETHERTYPE_IP, 0, DL_CLDLS, 0, 0);
  dlbindack(fd, buf);

  if (pkt){
    *len = length;
    return(pkt);
  } else {
    *len = -1;
    return(NULL);
  }
}


