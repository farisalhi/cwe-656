#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[128];
    char userbuf[128];
    char passbuf[128];
    const char *username = "admin";
    const char *password = "password";

    // prompt for credentials first
    printf("Enter login credentials to access your bank account...\n");
    // ask for username
    printf("Username: ");
    if (!fgets(userbuf, sizeof userbuf, stdin))
    {
        puts("\nEOF received, exiting.");
        return 1;
    }
    size_t len = strlen(userbuf);
    if (len && userbuf[len - 1] == '\n')
        userbuf[len - 1] = '\0';

    // ask for password
    printf("Password: ");
    if (!fgets(passbuf, sizeof passbuf, stdin))
    {
        puts("\nEOF received, exiting.");
        return 1;
    }
    len = strlen(passbuf);
    if (len && passbuf[len - 1] == '\n')
        passbuf[len - 1] = '\0';

    // they must both be correct (later we change this to match to any existing account in a fake database)
    // databse can just be a dictionary or something similar
    if (strcmp(userbuf, username) != 0 || strcmp(passbuf, password) != 0)
    {
        puts("Invalid credientials, exiting.");
        return 1;
    }

    // if login is successful, enter the program loop
    // we can do things here like access bank account, etc
    puts("Successfully logged in as Admin. Type \"logout\" to exit.");
    while (1)
    {
        printf("> ");
        if (!fgets(buf, sizeof buf, stdin))
        {
            puts("\nEOF received, exiting.");
            break;
        }
        /* strip trailing newline */
        size_t len2 = strlen(buf);
        if (len2 && buf[len2 - 1] == '\n')
            buf[len2 - 1] = '\0';

        if (strcmp(buf, "logout") == 0)
        {
            puts("Successfully logged out.");
            break;
        }
        printf("%s\n", buf);
    }

    return 0;
}