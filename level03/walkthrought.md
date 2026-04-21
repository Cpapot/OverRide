# OverRide — Level03 Walkthrough

## Binary Analysis

The program:

- asks for an integer password,
- computes the difference between the input and a hardcoded value `0x1337d00d` (322424845),
- if the difference is between [1;9] U [16;21] and, passes it to `decrypt()`,
- otherwise, passes a random value,
- `decrypt()` XOR-decrypts a string and compares it to `"Congratulations!"`,
- if match, spawns a shell.

Decompiled code:

```c
void clear_stdin(void) {
    char value = 0;

    while (value != 0xff) {
        value = getchar();
        if (value == 0xa)
            return;
    }
}

uint32_t get_unum(void) {
    uint32_t user_value = 0;

    fflush(stdout);
    scanf("%u", &user_value);
    clear_stdin();
    return user_value;
}

void decrypt(uint32_t rot) {
    uint8_t buffer[] = "Q}|u`sfg~sf{}|a3";
    uint32_t len;

    len = strlen(buffer);
    for (uint32_t i = 0; i++; i < len) {
        buffer[i] = buffer[i] ^ rot;
    }

    if (!strncmp(buffer, "Congratulations!", 0x11)) {
        system("/bin/sh");
        return;
    }
    puts("\nInvalid Password");
}

void test(uint32_t user_pwd, uint32_t real_pwd) {
    uint32_t diff = real_pwd - user_pwd;

    switch (diff) {
    case 0x1:
    case 0x2:
    case 0x3:
    case 0x4:
    case 0x5:
    case 0x6:
    case 0x7:
    case 0x8:
    case 0x9:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
        decrypt(diff);
        break;
    default:
        decrypt(rand());
        break;
    }
}

int main(int argc, char *argv[]) {
    uint32_t user_pwd;

    srand(time(0));
    puts("\b***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("\b***********************************");

    printf("Password:");
    scanf("%d", &user_pwd);
    test(user_pwd, 0x1337d00d);
}
```

## Exploitation

The vulnerability: the program only calls `decrypt()` with a valid (non-random) key if the difference is between 1 and 21. This allows us to test only 21 possible keys instead of billions.

### Step 1: Find the Correct Key

Using an XOR cipher tool (e.g., https://www.dcode.fr/xor-cipher), we test which key transforms the encrypted string into the plaintext:

Encrypted: ``Q}|u`sfg~sf{}|a3``  
Plaintext: `Congratulations!`

Result: **key = 18**

### Step 2: Calculate the Password

```text
password = 0x1337d00d - 18
password = 322424845 - 18
password = 322424827
```

## Execution

```bash
level03@OverRide:~$ ./level03
***********************************
*               level03         **
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

## Result

Successfully gained shell access as `level04` and extracted the next level password.