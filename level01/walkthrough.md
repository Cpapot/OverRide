
char a_user_name[0x100]; // 256

int verify_user_name() {
    puts("verifying username....\n");
    return strncmp("dat_wil", a_user_name, 7);
}

int verify_user_pass(char *password) {
    return strncmp("admin", password, 5);
}

int main() {
    char buffer[0x40]; // 64 ; ESP + 0x1c
    int ret = 0; // 0x5c

    memset(buffer, 0, 0x40);

    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    fgets(a_user_name, 0x100, stdin); // 256

    ret = verify_user_name();
    if (ret) {
        puts("nope, incorrect username...\n");
        return 1;
    }

    puts("Enter Password: ");
    fgets(buffer, 0x64, stdin); // 100
    ret = verify_user_pass(buffer);
    if (ret || !ret) {
        puts("nope, incorrect password...\n");
        return 1;
    }
    
    return 0;
}

dans le code on voit qu'on a deux fgets et que le deuxieme ecrit jusqua 0x64 dans le buffer de taille 0x40 on a donc un buffer overflow on doit pouvoir executer un shellcode que lon va stocker dans le buffer de lusername (voir lautre methode)