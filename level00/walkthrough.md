# OverRide — Level00 Walkthrough

## Binary Analysis

The program:

- prints a banner,
- asks for a password using `scanf("%d", &result)`,
- compares the input to `0x149c` (hexadecimal),
- spawns a shell (`/bin/sh`) if the condition is true.

Observed code:

```c
int main() {
    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");

    printf("Password:");

    int result;
    scanf("%d", &result);

    if (result == 0x149c) { // 5276
        puts("\nAuthenticated!");
        system("/bin/sh");
        return 0;
    }
    puts("\nInvalid Password!");
    return 1;
}
```

## Exploit

The check is made against `0x149c`, which is **5276** in decimal.

So the correct input is:

```text
5276
```

## Execution

```bash
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

## Result

Successfully gained access as `level01` and retrieved the next level password.