#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[128];
    char userbuf[128];
    char passbuf[128];

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

    // check creds against users.txt
    FILE *fp = fopen("users.csv", "r");
    if (!fp)
    {
        perror("Error opening users.csv");
        return 1;
    }

    int authenticated = 0;
    char line[256];
    char db_user[128];
    char db_pass[128];
    char db_balance[128] = "0";

    // san through the file and check if any credentials pass
    while (fgets(line, sizeof(line), fp))
    {
        // strip newline
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n')
        {
            line[l - 1] = '\0';
        }

        // parse username
        char *token = strtok(line, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_user, token, sizeof(db_user) - 1);
        db_user[sizeof(db_user) - 1] = '\0';

        // parse passowrd
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_pass, token, sizeof(db_pass) - 1);
        db_pass[sizeof(db_pass) - 1] = '\0';

        // parse balance
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_balance, token, sizeof(db_balance) - 1);
        db_balance[sizeof(db_balance) - 1] = '\0';

        // check credentials
        if (strcmp(userbuf, db_user) == 0 && strcmp(passbuf, db_pass) == 0)
        {
            authenticated = 1;
            break;
        }
    }
    fclose(fp);

    if (!authenticated)
    {
        puts("Invalid credientials, exiting.");
        return 1;
    }

    // if login is successful, enter the program loop
    // we can do things here like access bank account, etc
    printf("Successfully logged in as %s. Type \"logout\" to exit.\n", userbuf);
    while (1)
    {
        printf("> ");
        if (!fgets(buf, sizeof buf, stdin))
        {
            puts("\nEOF received, exiting.");
            break;
        }

        // strip newline
        size_t len2 = strlen(buf);
        if (len2 && buf[len2 - 1] == '\n')
            buf[len2 - 1] = '\0';

        // check for logout
        if (strcmp(buf, "logout") == 0)
        {
            puts("Successfully logged out.");
            break;
        }

        if (strcmp(buf, "balance") == 0)
        {
            printf("$%s\n", db_balance);
        }
    }

    return 0;
}