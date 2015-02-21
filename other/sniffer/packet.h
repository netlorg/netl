#include "globals.h"




struct iphdr {
    unsigned char version;
    unsigned char tos;
    unsigned char tot_len[2];
    unsigned char id[2];
    unsigned char frag_off[2];
    unsigned char ttl;
    unsigned char protocol;
    unsigned char check[2];
    unsigned char saddr[4];
    unsigned char daddr[4];
    };

struct tcphdr {
    unsigned char source[2];
    unsigned char dest[2];
    unsigned char seq[4];
    unsigned char ack_seq[4];
    unsigned char flags[2];
    unsigned char window[2];
    unsigned char check[2];
    unsigned char urg_ptr[2];
    };

/*
 * A structure which contains all of the parts of a packet
 */

struct PACKET {
    struct iphdr IP;
    struct tcphdr TCP;
    char DATA[PACKET_LENGTH];
    };

struct CONNECTION {
    unsigned char protocol;
    unsigned char saddr[4];
    unsigned char daddr[4];
    unsigned char source[2];
    unsigned char dest[2];
    unsigned char seq[4];
    unsigned char ack_seq[4];
    };


