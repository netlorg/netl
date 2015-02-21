#include "includes.h"
#include "anti_sniff.h"

int send_raw_frame(HDEV fd, void *pkt, int len, int flags);
HDEV open_net_intf(int value);

#define BHP(a) ((struct bpf_hdr *)a)


#ifdef XXX
/*
 * the code herein is dervied from libpcap.
 */
static	u_char	*buf = NULL;
static	int	bufsize = 0, timeout = 1;
#endif


HDEV open_net_intf(int value){
  struct bpf_version bv;
  struct timeval to;
  struct ifreq ifr;
  char bpfname[16];
  char *intName, *intPtr;
  int fd, i;

  for (i = 0; i < 16; i++) {
    (void) sprintf(bpfname, "/dev/bpf%d", i);
    if ((fd = open(bpfname, O_RDWR)) >= 0)
      break;
  }
  if (i == 16) {
    fprintf(stderr, "no bpf devices available as /dev/bpfxx\n");
    return -1;
  }

  if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
    perror("BIOCVERSION");
    return -1;
  }
  if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION) {
    fprintf(stderr, "kernel bpf (v%d.%d) filter out of date:\n",
 		bv.bv_major, bv.bv_minor);
    fprintf(stderr, "current version: %d.%d\n", 
                    BPF_MAJOR_VERSION, BPF_MINOR_VERSION);
    return -1;
  }

/*	(void) strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name)); */
  intName = getenv(ANTI_INTERFACE);
  if (!intName)
    (void) strncpy(ifr.ifr_name, DEVICENAME, sizeof(ifr.ifr_name)); 
  else {
    intPtr = strrchr(intName, '/');
    if (intPtr)
      intName = ++intPtr;
    (void) strncpy(ifr.ifr_name, intName, sizeof(ifr.ifr_name));
  }

  if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
    fprintf(stderr, "%s(%d):", ifr.ifr_name, fd);
    perror("BIOCSETIF");
    exit(1);
  }

#ifdef XXX
  /*
   * get kernel buffer size
   */
  if (ioctl(fd, BIOCGBLEN, &bufsize) == -1) {
    perror("BIOCSBLEN");
    exit(-1);
  }

  buf = (u_char*)malloc(bufsize);
#endif

  /*
   * set the timeout
   */
#ifdef XXX
  timeout = 1; /* not needed --- get rid of */
#endif
  to.tv_sec = 1;
  to.tv_usec = 0;

  if (ioctl(fd, BIOCSRTIMEOUT, (caddr_t)&to) == -1) {
    perror("BIOCSRTIMEOUT");
    exit(-1);
  }

  (void) ioctl(fd, BIOCFLUSH, 0);
  return fd;
}


/*
 * output an IP packet onto a fd opened for /dev/bpf
 */
int send_raw_frame(HDEV fd, void *pkt, int len, int flags){
			
  if (write(fd, pkt, len) == -1) {
    perror("send");
    return(FALSE);
  }

  return(TRUE);
}

void *recv_raw_frame(HDEV fd, int *len){
  int c;
  char *bp, *ep, *buf;
  int bufsize=0;
  
  /*                             
   * get kernel buffer size
   */
  if (ioctl(fd, BIOCGBLEN, &bufsize) == -1) {
    perror("BIOCSBLEN");
    exit(-1);  
  }                                                 

  buf = (char *)malloc(bufsize);
  if (!buf){
    perror("malloc");
    exit(1);
  }

  do {                                         
    c = read(fd, buf, bufsize);
  } while (c == -1  && errno == EINTR); 
  /* lets get rid of this below - the return of 0 means that someone is writing
     to the descriptor - we should be able to get around this with playing
     with O_NDELAY or O_NONBLOCK on the file descriptor. As it is we 
     push and pop the stack a bunch here going into and out of this routine.
  */
  if (c == 0){
    *len = -1;
    return(NULL); 
  }
  bp = buf;
  ep = buf + c;                      
  while (bp < ep) {                 
    if (BHP(bp)->bh_caplen > SIZE_ETHER_H){
      *len = BHP(bp)->bh_caplen - BHP(bp)->bh_hdrlen; 
      return(bp + BHP(bp)->bh_hdrlen);
    }
    /* filter(bp + BHP(bp)->bh_hdrlen + SIZE_ETHER_H,
             BHP(bp)->bh_caplen - SIZE_ETHER_H);  */ 
    bp += BPF_WORDALIGN(BHP(bp)->bh_hdrlen + BHP(bp)->bh_caplen);
  }                             
  *len = BHP(bp)->bh_caplen - BHP(bp)->bh_hdrlen;
  return(bp + BHP(bp)->bh_hdrlen);
}
