#include <stdio.h>
#include <string.h>

/**
 * This file contains a program that contains a simple "bug" in order to demonstrate a
 * basic patching workflow without any additional complexity introduced by reverse engineering
 * the program or understanding the patch.

 * The "bug" in this program is that the user misinterpretted the return value of strcmp, assuming
 that
  != 0 means the strings are equal
 * and control flow falls through to print the secret info.
 *
 * We would like to patch this programs condition to:
 * if (argc <= 1 || strcmp(argv[1], "PASS")) {return -1;}
 */

int main(int argc, char** argv) {
    if (argc <= 1 || !strcmp(argv[1], "PASS")) {
        return -1;
    }

    printf("secret info");
    return 0;
}