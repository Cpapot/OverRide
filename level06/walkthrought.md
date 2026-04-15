# OverRide — Level06 Walkthrough

## Binary Analysis

The binary asks for two values:

- a `login`,
- a `serial`.

It then calls `auth(login, serial)`. If the function returns `0`, it prints `Authenticated!` and spawns a shell.

Decompiled code:

```c
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
```

## Exploitation Strategy

The `auth()` function includes an anti-debug check (`ptrace`), but the serial generation logic is fully reversible.

So instead of debugging live, we can reimplement the serial computation in a helper program and generate the valid serial for any login.

## Recreate Serial Calculation

After reimplementing the algorithm locally (see main.c):

```bash
level06@OverRide:/tmp$ ./a.out cpapot
login: cpapot, serial: 6232800
```

## Use Valid Credentials

```bash
level06@OverRide:~$ ./level06
***********************************
*               level06           *
***********************************
-> Enter Login: cpapot
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6232800
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

## Result

Successfully authenticated as `level07` and retrieved the next password.