#include <stdio.h>
#include <unistd.h>

int main() {
	// Read from stdin, sleep for 1 second and print it
	char buffer[100];
	while (1) {
		if (fgets(buffer, 100, stdin) == 0)
			break;
		sleep(1);
		printf("%s", buffer);
	}
	return 0;
}
