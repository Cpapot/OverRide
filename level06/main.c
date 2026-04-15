#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned int bin;
    int len;

    len = strnlen(argv[1], 32);
    if (len < 6)
        return 1;

    bin = (argv[1][3] ^ 0x1337U) + 0x5eeded;
    for (int i = 0; i < len; i++) {
        if (argv[1][i] < 32 || argv[1][i] > 127)
            return 1;
        bin += (argv[1][i] ^ bin) % 1337;
    }
    printf("login: %s, serial: %d\n", argv[1], bin);
}