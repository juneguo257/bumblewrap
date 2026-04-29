#include <unistd.h>
#include <stdio.h>

int main() {
    char *const argv[] = {
        "/opt/bumblewrap/bumblewrap.py",
        "/usr/bin/python3",
        "/opt/bumblewrap/demo/bash-harness.py",
        NULL
    };

    execv(argv[0], argv);
    perror("execv");
    return 1;
}