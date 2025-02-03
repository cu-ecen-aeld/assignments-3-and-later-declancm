#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    openlog(NULL, 0, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Invalid number of arguments");

        printf("ERROR: Expected 2 arguments\n");
        printf("    1. file path\n");
        printf("    2. text string\n");

        return 1;
    }

    char *file_path = argv[1];
    char *text_string = argv[2];

    syslog(LOG_DEBUG, "Writing %s to %s", text_string, file_path);

    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        char *error = strerror(errno);
        syslog(LOG_ERR, "Failed to open file: %s", error);

        return 1;
    }

    fprintf(file, "%s\n", text_string);

    fclose(file);

    return 0;
}
