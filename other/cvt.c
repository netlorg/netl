#include <netinet/in.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
	int i;
	char buffer[255];

	while(fgets(buffer, 255, stdin)) {
		printf("%d\n", htons(atoi(buffer)));
	}
}
