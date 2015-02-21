#include "includes.h"
#include "anti_sniff.h"

int getnetmask(char *dev, struct in_addr *iaddr);
int getipaddr(char *dev, struct in_addr *iaddr);
struct ether_addr *ether_aton (char *s);

int getIPfromPkt(char *pkt, int len, char *holder){

  struct ip iph;

  if (len < SIZE_IP_H)
    return FALSE; 

  memcpy((char *)&iph, pkt, sizeof(struct ip));

  memcpy(holder, inet_ntoa((struct in_addr)iph.ip_src), MAX_LEN);
  return TRUE;
}

int validTarget(char *target_address){
  struct in_addr target, localIP, network;
  char *devname, *devPtr;

/* note that we should be using something like inet_aton instead of
   inet_addr since INADDR_NONE (0xffffffff) is a valid broadcast
   address but inet_addr cannot return that since it indicates
   failure. Alas alak solaris doesn't have inet_aton!  .mudge */

  target.s_addr = inet_addr(target_address);
  if (target.s_addr == -1){
    printf("error parsing target address\n");
    return FALSE;
  }

  devname = getenv(ANTI_INTERFACE);
  if (!devname){
    getnetmask(DEVICENAME, (struct in_addr *)&network);
    getipaddr(DEVICENAME, (struct in_addr *)&localIP);
  } else {
    devPtr = strrchr(devname, '/');
    if (devPtr)
      devname = ++devPtr;
    getnetmask(devname, (struct in_addr *)&network);
    getipaddr(devname, (struct in_addr *)&localIP);
  }


  if ((target.s_addr & network.s_addr) == (localIP.s_addr & network.s_addr))
    return TRUE;
  else
    return FALSE;

}

int make_ip(unsigned long *theip, char *thestring){
  struct in_addr addr;
  struct hostent *host;

  addr.s_addr = inet_addr(thestring);

  if (addr.s_addr == -1){
    host = (struct hostent *)gethostbyname((char *)thestring);
    if (!host){
      return(FALSE);
    }
    memcpy(&addr, host->h_addr, sizeof(unsigned long));
  }

  memcpy((char *)theip, (char *)&addr.s_addr, sizeof(unsigned long));
  return(TRUE);
}

int make_eth_addr(struct ether_addr *dest, char *target){
  struct ether_addr *localAddr;

  localAddr = (struct ether_addr *)ether_aton((char *)target);
  if (localAddr == NULL)
    return FALSE;

  memcpy(dest, localAddr, sizeof(struct ether_addr));

  return TRUE;
}
