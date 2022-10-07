int printf(const char *format, ...);
int puts(const char *s);

int fizz_buzz(int n) {
        for (int i = 0; i < n; i++) {
                if (i % 3 == 0) {
                        printf("Fizz");
                }
                if (i % 5 == 0) {
                        printf("Buzz");
                }
                if (i % 5 != 0 && i % 3 != 0) {
                        printf("%d", i);
                }
                puts("");
        }
        return 0;
}

int main(int argc, char* argv[]) {
        fizz_buzz(100);
        return 0;
}
