#include <stdio.h>

int main()
{
    printf("env shellcode addr: %p\n", getenv("SHELLCODE"));
}