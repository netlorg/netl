#include "includes.h"
#include "anti_sniff.h"


int getetheraddr(HDEV fd, struct ether_addr *eaddr){
  char *intName, device[MAX_LEN];
  struct ifreq ifr;

  memset(&ifr, '\0', sizeof(ifr));

  intName = getenv(ANTI_INTERFACE);
  if (!intName)
    strncpy(ifr.ifr_name, DEVICENAME, sizeof(device));
  else
    strncpy(ifr.ifr_name, intName, sizeof(device));

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ){
    perror("ioctl getetheraddr SIOCGIFHWADDR : ");
    exit(1);
  }
  
  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER){
    fprintf(stderr, "Hardware family for %s does not claim to be ETHER\n",
             ifr.ifr_name);
    return FALSE;
  }

  memcpy((char *)eaddr, &(ifr.ifr_ifru.ifru_addr.sa_data), 
         sizeof(struct ether_addr));

  return TRUE;
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

