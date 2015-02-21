#include <string.h>

int Find(char * String, char * Match, int length2)
{
int length;
int i, k;
char buf[100];

length = strlen(Match);

if(length2 < length)
    return 0;

for(i = 0; i < (length2 - length); i++)
    {
    for(k = 0; k < length; k++)
        buf[k] = String[k + i];
    if(!strncmp(buf,Match,length))
        return 1;
    }

return 0;
}
