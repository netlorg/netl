#include <linux/if_ether.h>
#include <linux/if.h>
#include <string.h>

#include "inet.h"
#include "sniff.h"
#include "globals.h"

/* Globals */



int Sock;
struct ifreq oldifr, ifr;

void init(char * DEV)
{

Sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));

/*
 * Stores device name to access in ifr and oldifr
 */
strcpy(ifr.ifr_name, DEV);
strcpy(oldifr.ifr_name, DEV);

/*
 * Stores the cards current setting into ifr and oldifr
 */
if(ioctl(Sock, SIOCGIFFLAGS, &ifr) < 0)
    {
    printf("Unable to get %s flags.\n", DEV);
    exit(1);
    }

if(ioctl(Sock, SIOCGIFFLAGS, &oldifr) < 0)
    {
    printf("Unable to get %s flags.\n", DEV);
    exit(1);
    }

/*
 * Sets ifr's flags to include Promiscuous Mode
 */
ifr.ifr_flags |= IFF_PROMISC;

/*
 * Sets devices flags to that of ifr's
 */
if(ioctl(Sock, SIOCSIFFLAGS, &ifr) < 0)
    {
    printf("Unable to set %s flags.\n", DEV);
    exit(1);
    }
printf("%s device has been successfully configured.\n", DEV);
}

void Get_Packet(char buf[PACKET_LENGTH])
{
int length;
struct sockaddr saddr;
int sizeaddr;

length = recvfrom(Sock, buf, PACKET_LENGTH, 0, &saddr, &sizeaddr);


}

struct PACKET * Convert_Packet(char buf[PACKET_LENGTH])
{
int i;
char tmp[PACKET_LENGTH];
struct PACKET Holder;

/*
 * Copy over ip information
 */
for(i = 14; i < 34; i++)
    tmp[i - 14] = buf[i];
/*
 * Copy tmp to iphdr structure
 */
bcopy(tmp, &Holder.IP, 20);

/*
 * Copy over tcp information
 */
for(i = 34; i < 54; i++)
    tmp[i - 34] = buf[i];
bcopy(tmp, &Holder.TCP, 20);

for(i = 54; i < PACKET_LENGTH; i++)
    tmp[i - 54] = buf[i];
bcopy(tmp, &Holder.DATA, (PACKET_LENGTH - 54));

return &Holder;
}

void Display_Packet(struct PACKET * Out)
{
int i,k;      /* loop variables */
int dlength;



/*
 * Display ip Information
 */
printf("Header Length: %d   Service Type: %d",
        Out->IP.version & 0x000f, Out->IP.tos & 0x00ff);
printf("    Total Length: %d\n",
        (Out->IP.tot_len[0] & 0x00ff) * 256 + (Out->IP.tot_len[1] & 0x00ff));
printf("Id: %d    FragFlags: %d\n",
        (Out->IP.id[0] & 0x00ff) * 256 + (Out->IP.id[1] & 0x00ff),
        (Out->IP.frag_off[0] & 0x00ff) * 256 + (Out->IP.frag_off[1] & 0x00ff))
;
printf("TTL: %d    Protocol: %d    HeaderChecksum: %d\n",
        Out->IP.ttl & 0x00ff, Out->IP.protocol & 0x00ff,
        (Out->IP.check[0] & 0x00ff) * 256 + (Out->IP.check[1] & 0x00ff));
printf("Source Address: %d.%d.%d.%d    Destination Address: %d.%d.%d.%d\n",
        Out->IP.saddr[0] & 0x00ff, Out->IP.saddr[1] & 0x00ff,
        Out->IP.saddr[2] & 0x00ff, Out->IP.saddr[3] & 0x00ff,
        Out->IP.daddr[0] & 0x00ff, Out->IP.daddr[1] & 0x00ff,
        Out->IP.daddr[2] & 0x00ff, Out->IP.daddr[3] & 0x00ff);

/*
 * Display tcp information
 */

printf("Source Port: %d    Destination Port: %d\n",
        ((Out->TCP.source[0] & 0x00ff) * 256) + (Out->TCP.source[1] & 0x00ff),
        ((Out->TCP.dest[0] & 0x00ff) * 256) + (Out->TCP.dest[1] & 0x00ff));
printf("Sequence Number: %ld    Acknowledgement Number: %ld\n",
        (Out->TCP.seq[0] & 0x00ff) * 65536 + (Out->TCP.seq[1] & 0x00ff) * 4096
        + (Out->TCP.seq[2] & 0x00ff) * 256 + (Out->TCP.seq[3] & 0x00ff),
        (Out->TCP.ack_seq[0] & 0x00ff) * 65536 + (Out->TCP.ack_seq[1] & 0x00ff
) * 4096
        + (Out->TCP.ack_seq[2] & 0x00ff) * 256 + (Out->TCP.ack_seq[3] & 0x00ff
));
printf("TCP Header length: %d    Checksum: %d    Urgent Pointer: %d\n",
        (Out->TCP.flags[0] & 0x00f0) >> 4, (Out->TCP.check[0] & 0x00ff) * 256
+
        (Out->TCP.check[1] & 0x00ff), (Out->TCP.urg_ptr[0] & 0x0ff) * 256 +
        (Out->TCP.urg_ptr[1] & 0x00ff));

/*
 * Display data information
 */

/*
 * Data length = Total length - IP header length - TCP Header length
 */
dlength = (Out->IP.tot_len[0] & 0x00ff) * 256 + (Out->IP.tot_len[1] & 0x00ff)
          - (Out->IP.version & 0x000f) * 4 - ((Out->TCP.flags[0] & 0x00f0) >>
4) * 4;

printf("Data Length: %d\n", dlength);
if((Out->IP.tot_len[0] & 0x00ff) > PACKET_LENGTH)
    dlength = PACKET_LENGTH - (Out->IP.version & 0x00ff) * 4 -
              ((Out->TCP.flags[0] & 0x00ff) >> 4) * 4;
printf("-------------------------------------------------------------\n");
for(i = 0 + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4;
        i <  (dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4);
        i += 16)
    {
    if((dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4) - i >= 16)
        for(k = 0; k < 16; k++)
            if((Out->DATA[i + k] & 0x00ff) < 16)
                printf("0%x", Out->DATA[i + k] & 0x00ff);
            else
                printf("%x", Out->DATA[i + k] & 0x00ff);
    else
        for(k = 0; k < (dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) *
4) - i; k++)
            if((Out->DATA[i + k] & 0x00ff) < 16)
                printf("0%x", Out->DATA[i + k] & 0x00ff);
            else
                printf("%x", Out->DATA[i + k] & 0x00ff);
    printf("                ");
    if((dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4) - i >= 16)
        for(k = 0; k < 16; k++)
            if((Out->DATA[i + k] & 0x00ff) > 39)
                printf("%c", Out->DATA[i + k]);
            else
                printf(".");
    else
        for(k = 0; k < (dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) *
4) - i; k++)
            if((Out->DATA[i + k] & 0x00ff) > 39)
                printf("%c", Out->DATA[i + k]);
            else
                printf(".");
    printf("\n");
    }
printf("-------------------------------------------------------------\n");
}

int Unique(struct CONNECTION List[256], struct PACKET * Out, int count)
{
int i,j;    /* Loop counters */
int flag = -1;
int num;    /* Number where non uniqueness occurs */

/*
 * Scan through list of connections and see if Out differs.
 */
for(i = 0; i < count; i++)
    {
    /*
     * Checks if this is a non-unique connection
     */
    if((Out->IP.protocol & 0x00ff) == (List[i].protocol & 0x00ff))
    if((Out->IP.saddr[0] & 0x00ff) == (List[i].saddr[0] & 0x00ff))
    if((Out->IP.saddr[1] & 0x00ff) == (List[i].saddr[1] & 0x00ff))
    if((Out->IP.saddr[2] & 0x00ff) == (List[i].saddr[2] & 0x00ff))
    if((Out->IP.saddr[3] & 0x00ff) == (List[i].saddr[3] & 0x00ff))
    if((Out->IP.daddr[0] & 0x00ff) == (List[i].daddr[0] & 0x00ff))
    if((Out->IP.daddr[1] & 0x00ff) == (List[i].daddr[1] & 0x00ff))
    if((Out->IP.daddr[2] & 0x00ff) == (List[i].daddr[2] & 0x00ff))
    if((Out->IP.daddr[3] & 0x00ff) == (List[i].daddr[3] & 0x00ff))
    if((Out->TCP.source[0] & 0x00ff) == (List[i].source[0] & 0x00ff))
    if((Out->TCP.source[1] & 0x00ff) == (List[i].source[1] & 0x00ff))
    if((Out->TCP.dest[0] & 0x00ff) == (List[i].dest[0] & 0x00ff))
    if((Out->TCP.dest[1] & 0x00ff) == (List[i].dest[1] & 0x00ff))
        flag = i;
    }

if (flag == -1)
    {
    List[count].protocol = Out->IP.protocol;
    List[count].saddr[0] = Out->IP.saddr[0];
    List[count].saddr[1] = Out->IP.saddr[1];
    List[count].saddr[2] = Out->IP.saddr[2];
    List[count].saddr[3] = Out->IP.saddr[3];
    List[count].daddr[0] = Out->IP.daddr[0];
    List[count].daddr[1] = Out->IP.daddr[1];
    List[count].daddr[2] = Out->IP.daddr[2];
    List[count].daddr[3] = Out->IP.daddr[3];
    List[count].source[0] = Out->TCP.source[0];
    List[count].source[1] = Out->TCP.source[1];
    List[count].dest[0] = Out->TCP.dest[0];
    List[count].dest[1] = Out->TCP.dest[1];
    List[count].seq[0] = Out->TCP.seq[0];
    List[count].seq[1] = Out->TCP.seq[1];
    List[count].seq[2] = Out->TCP.seq[2];
    List[count].seq[3] = Out->TCP.seq[3];
    List[count].ack_seq[0] = Out->TCP.ack_seq[0];
    List[count].ack_seq[1] = Out->TCP.ack_seq[1];
    List[count].ack_seq[2] = Out->TCP.ack_seq[2];
    List[count].ack_seq[3] = Out->TCP.ack_seq[3];
    }

return flag;
}

/*
 * Display unique connections
 */

void Display_Connections(struct CONNECTION List[256], int count)
{
int i;

for(i = 0; i < count; i++)
    {
    printf("#%d, P: %d, ", i, List[i].protocol & 0x00ff);
    printf("SA: %d.%d.%d.%d, DA: %d.%d.%d.%d, ",
        List[i].saddr[0] & 0x00ff, List[i].saddr[1] & 0x00ff,
        List[i].saddr[2] & 0x00ff, List[i].saddr[3] & 0x00ff,
        List[i].daddr[0] & 0x00ff, List[i].daddr[1] & 0x00ff,
        List[i].daddr[2] & 0x00ff, List[i].daddr[3] & 0x00ff);
    printf("SP: %d, DP: %d\n",
        (List[i].source[0] & 0x00ff) * 256 + (List[i].source[1] & 0x00ff),
        (List[i].dest[0] & 0x00ff) * 256 + (List[i].dest[1] & 0x00ff));
    }
printf("---------------------------------------------------------\n");
}

void Set_Connection(struct PACKET * Out, struct CONNECTION List[256])
    {
    List[0].protocol = Out->IP.protocol;
    List[0].saddr[0] = Out->IP.saddr[0];
    List[0].saddr[1] = Out->IP.saddr[1];
    List[0].saddr[2] = Out->IP.saddr[2];
    List[0].saddr[3] = Out->IP.saddr[3];
    List[0].daddr[0] = Out->IP.daddr[0];
    List[0].daddr[1] = Out->IP.daddr[1];
    List[0].daddr[2] = Out->IP.daddr[2];
    List[0].daddr[3] = Out->IP.daddr[3];
    List[0].source[0] = Out->TCP.source[0];
    List[0].source[1] = Out->TCP.source[1];
    List[0].dest[0] = Out->TCP.dest[0];
    List[0].dest[1] = Out->TCP.dest[1];
    List[0].seq[0] = Out->TCP.seq[0];
    List[0].seq[1] = Out->TCP.seq[1];
    List[0].seq[2] = Out->TCP.seq[2];
    List[0].seq[3] = Out->TCP.seq[3];
    List[0].ack_seq[0] = Out->TCP.ack_seq[0];
    List[0].ack_seq[1] = Out->TCP.ack_seq[1];
    List[0].ack_seq[2] = Out->TCP.ack_seq[2];
    List[0].ack_seq[3] = Out->TCP.ack_seq[3];
    }

int Data_Length(struct PACKET *Out)
{
return (Out->IP.tot_len[0] & 0x00ff) * 256 + (Out->IP.tot_len[1] & 0x00ff)
       - (Out->IP.version & 0x000f) * 4 - ((Out->TCP.flags[0] & 0x00f0) >> 4)
       * 4;
}

void Write_Data(struct PACKET * Out)
{
int dlength;
int i, k;

/*
 * Data length = Total length - IP header length - TCP Header length
 */
dlength = (Out->IP.tot_len[0] & 0x00ff) * 256 + (Out->IP.tot_len[1] & 0x00ff)
          - (Out->IP.version & 0x000f) * 4 - ((Out->TCP.flags[0] & 0x00f0) >>
4) * 4;
for(i = 0 + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4;
        i <  (dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4);
        i += 16)
    {
    if((dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) * 4) - i >= 16)
        for(k = 0; k < 16; k++)
            if((Out->DATA[i + k] & 0x00ff) > 39)
                printf("%c", Out->DATA[i + k]);
            else
                printf(".");
    else
        for(k = 0; k < (dlength + (((Out->TCP.flags[0] & 0x00f0) >> 4) - 5) *
4) - i; k++)
            if((Out->DATA[i + k] & 0x00ff) > 39)
                printf("%c", Out->DATA[i + k]);
            else
                printf(".");
    }
}


