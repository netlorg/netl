#include "includes.h"
#include "anti_sniff.h"


struct nlist nl[] = {
#define N_MBSTAT        0
        { "_mbstat" },
#define N_IPSTAT        1
        { "_ipstat" },
#define N_TCBTABLE      2
        { "_tcbtable" },
#define N_TCPSTAT       3
        { "_tcpstat" },
#define N_UDBTABLE      4
        { "_udbtable" },
#define N_UDPSTAT       5
        { "_udpstat" },
#define N_IFNET         6
        { "_ifnet" },
#define N_IMP           7
        { "_imp_softc" },
#define N_ICMPSTAT      8
        { "_icmpstat" },
#define N_RTSTAT        9
        { "_rtstat" },
#define N_UNIXSW        10
        { "_unixsw" },
#define N_IDP           11
        { "_nspcb"},
#define N_IDPSTAT       12
        { "_idpstat"},
#define N_SPPSTAT       13
        { "_spp_istat"},
#define N_NSERR         14
        { "_ns_errstat"},
#define N_CLNPSTAT      15
        { "_clnp_stat"},
#define IN_NOTUSED      16
        { "_tp_inpcb" },
#define ISO_TP          17
        { "_tp_refinfo" },
#define N_TPSTAT        18
        { "_tp_stat" },
#define N_ESISSTAT      19
        { "_esis_stat"},
#define N_NIMP          20
        { "_nimp"},
#define N_RTREE         21
        { "_rt_tables"},
#define N_CLTP          22
        { "_cltb"},
#define N_CLTPSTAT      23
        { "_cltpstat"},
#define N_NFILE         24
        { "_nfile" },
#define N_FILE          25
        { "_file" },
#define N_IGMPSTAT      26
        { "_igmpstat" },
#define N_MRTPROTO      27
        { "_ip_mrtproto" },
#define N_MRTSTAT       28
        { "_mrtstat" },
#define N_MFCHASHTBL    29
        { "_mfchashtbl" },
#define N_MFCHASH       30
        { "_mfchash" },
#define N_VIFTABLE      31
        { "_viftable" },
#define N_IPX           32
        { "_ipxcbtable"},
#define N_IPXSTAT       33
        { "_ipxstat"},
#define N_SPXSTAT       34
        { "_spx_istat"},
#define N_IPXERR        35
        { "_ipx_errstat"},
#define N_AHSTAT        36
        { "_ahstat"},
#define N_ESPSTAT       37
        { "_espstat"},
#define N_IP4STAT       38
        { "_ip4stat"},
#define N_DDPSTAT       39
        { "_ddpstat"},
#define N_DDPCB         40
        { "_ddpcb"},
        { ""},
};

kvm_t *kvmd;                              

void intpr(u_long ifnetaddr, char *, struct ether_addr *);
int  kread(u_long addr, char *buf, int size);


#ifdef XYZ
/* STUB */
main(){

#ifdef 0
  struct ether_addr eaddr;
  HDEV fd;

  fd = open_net_intf(-1);
  getetheraddr(fd, &eaddr);

  printf("ether addr = %s\n", ether_ntoa(&eaddr));
#endif

  struct in_addr iaddr;

  getnetmask(DEVICENAME, &iaddr);
  printf("%s\n", inet_ntoa(iaddr));

}
#endif

int getetheraddr(HDEV fd, struct ether_addr *eaddr){
  struct ifreq ifr;
  char *nlistf = NULL, *memf = NULL;
  char buf[1024];
  char intname[256];


  if( ioctl(fd, BIOCGETIF, &ifr) < 0){
    perror("ioctl");
    exit(1);
  }

  strncpy(intname, ifr.ifr_name, sizeof(intname));

  if ((kvmd = kvm_openfiles(nlistf, memf, NULL, O_RDONLY,
      buf)) == NULL) {
    fprintf(stderr, "kvm_open: %s\n", buf);
    exit(1);
  }

  if (kvm_nlist(kvmd, nl) < 0 || nl[0].n_type == 0) {
    if (nlistf)
      fprintf(stderr, "%s: no namelist\n", nlistf);
    else
      fprintf(stderr, "no namelist\n");
    exit(1);
  }

  intpr(nl[N_IFNET].n_value, intname, eaddr);
  return(TRUE);
}

void
intpr(u_long ifnetaddr, char *intname, struct ether_addr *eaddr){
  struct ifnet ifnet;
  union {
    struct ifaddr ifa;
    struct in_ifaddr in;
  } ifaddr;
  u_long ifaddraddr;
  struct ifnet_head ifhead; /* TAILQ_HEAD */
  char name[IFNAMSIZ];
  struct sockaddr_dl *sdl;
  struct sockaddr *sa;

 if (ifnetaddr == 0) {
   printf("ifnet: symbol not defined\n");
   return;
 }

 /*
  * Find the pointer to the first ifnet structure.  Replace
  * the pointer to the TAILQ_HEAD with the actual pointer
  * to the first list element.
  */
  if (kread(ifnetaddr, (char *)&ifhead, sizeof ifhead))
    return;

  ifnetaddr = (u_long)ifhead.tqh_first;
  ifaddraddr = 0;

  while (ifnetaddr){
    register char *cp;

    if (kread(ifnetaddr, (char *)&ifnet, sizeof ifnet))
      return;
    bcopy(ifnet.if_xname, name, IFNAMSIZ);
    name[IFNAMSIZ - 1] = '\0';      /* sanity */
    ifnetaddr = (u_long)ifnet.if_list.tqe_next;
    ifaddraddr = (u_long)ifnet.if_addrlist.tqh_first;

    if (strcmp(name, intname) == 0) {
      if (ifaddraddr != 0){
        if (kread(ifaddraddr, (char *)&ifaddr, sizeof ifaddr)) {
          ifaddraddr = 0;
          continue;
        }
#define CP(x) ((char *)(x))
        cp = (CP(ifaddr.ifa.ifa_addr) - CP(ifaddraddr)) +
               CP(&ifaddr); 
        sa = (struct sockaddr *)cp;
        sdl = (struct sockaddr_dl *)sa;
/*
        if (sdl->sdl_type == IFT_ETHER ||
            sdl->sdl_type == IFT_FDDI)
*/
/*          printf("%s\n", ether_ntoa((struct ether_addr *)LLADDR(sdl))); */
          memcpy((char *)eaddr, (char *)LLADDR(sdl), sizeof(struct ether_addr));
      }
    }
  }
}


/*
 * Read kernel memory, return 0 on success.
 */
int
kread(addr, buf, size)
        u_long addr;
        char *buf;
        int size;
{

        if (kvm_read(kvmd, addr, buf, size) != size) {
                (void)fprintf(stderr, "%s\n", kvm_geterr(kvmd));
                return (-1);
        }
        return (0);
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
