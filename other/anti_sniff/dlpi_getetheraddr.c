#include "includes.h"
#include "anti_sniff.h"

void dlphysaddrreq(int fd, u_long addrtype);
void dlphysaddrack(int fd, char *bufp);

#ifdef XXX
main(){
  struct in_addr iaddr;

  getipaddr("le0", &iaddr);
  printf("interface %s --- address %s\n", "le0", inet_ntoa(iaddr));

}
#endif

int getetheraddr(HDEV fd, struct ether_addr *eaddr){

  long buf[MAXDLBUF];
  union DL_primitives *dlp;

  dlp = (union DL_primitives *)buf;

  dlphysaddrreq(fd, DL_CURR_PHYS_ADDR);
  dlphysaddrack(fd, (char *)buf);

  memcpy(eaddr, ((char *)dlp + dlp->physaddr_ack.dl_addr_offset), 
         sizeof(struct ether_addr));

  return(TRUE);
}

int getipaddr(char *dev, struct in_addr *iaddr){
  int s;
  struct ifreq ifr;
  struct sockaddr_in *sin;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s == -1){
    perror("socket");
    exit(1);
  }

  strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)); 
  if (ioctl(s, SIOCGIFADDR, (struct ifreq *)&ifr) < 0){
    perror("SIOCGIFADDR");
    exit(1);
  }

  sin = (struct sockaddr_in *)&ifr.ifr_addr; 
  memcpy(iaddr, &sin->sin_addr, sizeof(struct in_addr));
  return(TRUE);
}

int getnetmask(char *dev, struct in_addr *iaddr){
  int s;
  struct ifreq ifr;  
  struct sockaddr_in *sin;
        
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s == -1){       
    perror("socket");    
    exit(1);            
  }                      
        
  strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
  if (ioctl(s, SIOCGIFNETMASK, (struct ifreq *)&ifr) < 0){
    perror("SIOCGIFNETMASK");
    exit(1);           
  }                      
        
  sin = (struct sockaddr_in *)&ifr.ifr_addr;
  memcpy(iaddr, &sin->sin_addr, sizeof(struct in_addr));
  return(TRUE);          
}

