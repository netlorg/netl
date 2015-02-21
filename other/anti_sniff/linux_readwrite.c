#include "includes.h"
#include "anti_sniff.h"

int send_raw_frame(HDEV fd, void *pkt, int len, int flags);
HDEV open_net_intf(int value);


HDEV open_net_intf(int value){
  struct ifreq ifr;
  int fd;
  char *intName;
  char devname[MAX_LEN];
  
  fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
  if (fd == -1){
    perror("open_net_intf : socket ");
    exit(1);
  }

  intName = getenv(ANTI_INTERFACE);
  if (!intName){
    snprintf(devname, sizeof(devname), "%s", DEVICENAME);
  } else {
    strncpy(devname, intName, sizeof(devname));
  }

  memset(&ifr, '\0', sizeof(ifr));
  strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));
 
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ){
    perror("ioctl SIOCGIFHWADDR ");
    exit(1);
  }
 
  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    fprintf(stderr, "unknown physical layer - 0x%x\n", ifr.ifr_hwaddr.sa_family);
    exit(1);
  }

  ifr.ifr_flags |= IFF_PROMISC;
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0 ){
    perror("ioctl SIOCSIFFLAGS ");
    exit(1);
  }

  return(fd);
}

/*
 * output an IP packet onto a fd opened for linux SOCK_PACKET
 */
int send_raw_frame(HDEV fd, void *pkt, int len, int flags){
			
  struct sockaddr sa;
  int ret;

  memset(&sa, '\0', sizeof(struct sockaddr));
  strncpy(sa.sa_data, "eth0", strlen("eth0"));

/*
  if (write(fd, pkt, len) == -1) {
    perror("send_raw_frame write ");
    return(FALSE);
  }
*/
  ret = sendto(fd, pkt, len, 0, &sa, sizeof(struct sockaddr));
  if (ret != len)
    return(FALSE);
  else
    return(TRUE);
}

void *recv_raw_frame(HDEV fd, int *len){
  unsigned char pkt[MAXDLBUF];
  void *retPkt;

  *len = recvfrom(fd, pkt, MAXDLBUF, 0, NULL, NULL);
  retPkt = malloc(*len);
  if (!retPkt) {
    perror("malloc : ");
    exit(1);
  }

  memcpy((char *)retPkt, pkt, *len);
   
  return(retPkt);
}

