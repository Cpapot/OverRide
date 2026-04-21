#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("env shellcode addr: %p\n", getenv("SHELLCODE"));
    return 0;
}