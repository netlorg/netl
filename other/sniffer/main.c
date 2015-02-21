#include "sniff.h"
#include "inet.h"
#include "find.h"

#include <string.h>

void main()
{
FILE * fd;
int i,j;
int choice;
char name[2];
char buf[500];
struct PACKET *Out;
struct CONNECTION List[256];
char View[256][50];
char Data[256][50];
struct CONNECTION Check[1];
int toggle = 0;
int count = 0;   /* Stores the number of unique connections */

/*strncpy(name, "lo\0", 3);*/
strncpy(name, "eth0\0", 5);

init(name);

while(1)
    {

    /*
     * Get the next packet to fly by the network
     */
    Get_Packet(buf);

    /*
     * Convert the buffer into a Packet type structure
     */
    Out = Convert_Packet(buf);

    /*
     * Display all of the packet information
     */
    Display_Packet(Out);

    /*
     * If the program detects login in the text it will then check
     * if the connection is unique
     */
        if(Unique(List, Out, count) == -1)
            {
            printf("Found a Unique connection\n");
            count = count + 1;
            Display_Connections(List, count);
            }

    }
}
