#include "packet.h"

/*
 * Header file for sniff functions
 */

void init(char *);

void Get_Packet(char buf[PACKET_LENGTH]);

struct PACKET * Convert_Packet(char *);

void Display_Packet(struct PACKET *);

int Unique(struct CONNECTION *, struct PACKET *, int);

void Set_Connection(struct PACKET *, struct CONNECTION *);

void Write_Data(struct PACKET *);

void Display_Connections(struct CONNECTION *, int);

int Data_Length(struct PACKET *);

