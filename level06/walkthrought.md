int auth(char *login, uint serial)
{
    int len;
    uint bin;
    int i;

    login[strcspn(login, "\n")] = '\0';
    len = strnlen(login, 32);
    if (len < 6)
        return 1;
    
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        puts("\x1b[32m.---------------------------.");
        puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
        puts("\x1b[32m\'---------------------------\'");
        return 1;
    }

    bin = (login[3] ^ 0x1337U) + 0x5eeded;
    for (i = 0; i < len; i++) {
        if (login[i] < 32 || login[i] > 127)
            return 1;
        bin += (login[i] ^ bin) % 1337;
    }

    if (serial != bin)
        return 1;
    
    return 0;
}

int main(void)
{
    char login[32];
    uint serial;
    int ret;

    puts("***********************************");
    puts("*\t\tlevel06\t\t  *");
    puts("***********************************");
    printf("-> Enter Login: ");
    fgets(login, 32, stdin);

    puts("***********************************");
    puts("***** NEW ACCOUNT DETECTED ********");
    puts("***********************************");
    printf("-> Enter Serial: ");
    scanf("%u", &serial);

    ret = auth(login, serial);
    if (ret == 0) {
        puts("Authenticated!");
        system("/bin/sh");
        return 0;
    }
    
    return 1;
}

main:
we can see that the program ask a login and a serial, give it to the auth function and if auth return 0 it open a shell.

auth:
the auth function prevents us from using gdb with ptrace, then it take login data to create a uint and compare this uint with serial if equal the function return 1.

so we need to find a login and a serial that pass the auth function. to do so we gonna recode the part of the auth function who convert login into serial.

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
    printf("login: %s, serial: %d", argv[1], bin);
}