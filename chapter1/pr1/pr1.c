#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void getFlag() {
	system("/bin/sh");
}

void replaceTo(int *ptr){*ptr = 20;}

void main() {
	int *ptr = malloc(sizeof(int));
	int temp = 10;
	memset(ptr, 0, sizeof(int));
	
	ptr = &temp;
	printf("[%d]\n", temp);
	replaceTo(ptr);
	printf("[%d]\n", temp);
	
	getFlag();	
}
