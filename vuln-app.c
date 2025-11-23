#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// struct to contain account info
typedef struct
{
    char fname[128];
    char lname[128];
    char username[128];
    char password[128];
    double balance;
} Account;

int get_creds(char userbuf[], char passbuf[])
{
    // prompt for credentials first
    printf("Enter your credentials to access your bank account...\n");
    // ask for username
    printf("Username: ");

    if (!fgets(userbuf, 128, stdin))
    {
        puts("\nEOF received, exiting.");
        return 1;
    }

    size_t len = strlen(userbuf);
    if (len && userbuf[len - 1] == '\n')
        userbuf[len - 1] = '\0';

    // ask for password
    printf("Password: ");
    if (!fgets(passbuf, 128, stdin))
    {
        puts("\nEOF received, exiting.");
        return 1;
    }

    len = strlen(passbuf);
    if (len && passbuf[len - 1] == '\n')
        passbuf[len - 1] = '\0';

    return 0;
}

// function to search through the given file, authenticate and fill the account given by the pointer
int authenticate(char *file, char userbuf[], char passbuf[], Account *account)
{
    char line[256];
    char db_fname[128];
    char db_lname[128];
    char db_uname[128];
    char db_pass[128];
    char db_balance[128] = "0";
    int authenticated = 0;

    // open users file
    FILE *fp = fopen(file, "r");
    if (!fp)
    {
        printf("error?\n");
        fprintf(stderr, "Error opening %s\n", file);
        return 0;
    }

    // scan through the file and check if any credentials pass
    while (fgets(line, sizeof(line), fp))
    {
        // strip newline
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n')
        {
            line[l - 1] = '\0';
        }

        // parse first name
        char *token = strtok(line, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_fname, token, sizeof(db_fname) - 1);
        db_fname[sizeof(db_fname) - 1] = '\0';

        // parse last name
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_lname, token, sizeof(db_lname) - 1);
        db_lname[sizeof(db_lname) - 1] = '\0';

        // parse username
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_uname, token, sizeof(db_uname) - 1);
        db_uname[sizeof(db_uname) - 1] = '\0';

        // parse password
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
        if (strcmp(userbuf, db_uname) == 0 && strcmp(passbuf, db_pass) == 0)
        {
            authenticated = 1;
            break;
        }
    }
    fclose(fp);
    // copy the buffer values into the account
    strncpy(account->fname, db_fname, sizeof(account->fname) - 1);
    account->fname[sizeof(account->fname) - 1] = '\0';

    strncpy(account->lname, db_lname, sizeof(account->lname) - 1);
    account->lname[sizeof(account->lname) - 1] = '\0';

    strncpy(account->username, db_uname, sizeof(account->username) - 1);
    account->username[sizeof(account->username) - 1] = '\0';

    strncpy(account->password, db_pass, sizeof(account->password) - 1);
    account->password[sizeof(account->password) - 1] = '\0';

    account->balance = atof(db_balance);

    return authenticated;
}

void user_session(Account *user_account)
{
    char option[12];

    const char *user_message = "~~~~~~~~~~~~~~~~~\n[1] Check Balance\n[2] Log out\n~~~~~~~~~~~~~~~~~\n";

    printf("Successfully logged in as user: %s %s\n", user_account->fname, user_account->lname);

    // user session loop
    while (1)
    {
        printf("%s\n", user_message);
        printf("> ");

        if (!fgets(option, sizeof option, stdin))
        {
            printf("\nEOF received, exiting.");
            break;
        }

        // strip newline
        size_t len2 = strlen(option);
        if (len2 && option[len2 - 1] == '\n')
            option[len2 - 1] = '\0';

        // check for options (first character)
        switch (option[0])
        {
        case '1':
        {
            printf("Balance: $%.2f\n", user_account->balance);
            break;
        }
        case '2':
        {
            printf("Logging out...");
            return;
        }
        default:
        {
            printf("Unknown option. Please try again.");
            break;
        }
        }
    }
}

// print all accounts and their balances
void print_accounts()
{
    char line[256];
    char db_fname[128];
    char db_lname[128];
    char db_uname[128];
    char db_pass[128];
    char db_balance[128] = "0";

    // open users file
    FILE *fp = fopen("users.csv", "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening users.csv\n");
        return;
    }

    const char *border = "+-----------------+-----------------+-----------------+-----------------+------------+";

    // print table header
    printf("%s\n", border);
    printf("| %-15s | %-15s | %-15s | %-15s | %-10s |\n", "First Name", "Last Name", "Username", "Password", "Balance");
    printf("%s\n", border);

    // scan through the file and print each account
    while (fgets(line, sizeof(line), fp))
    {
        // strip newline
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n')
        {
            line[l - 1] = '\0';
        }

        // parse first name
        char *token = strtok(line, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_fname, token, sizeof(db_fname) - 1);
        db_fname[sizeof(db_fname) - 1] = '\0';

        // parse last name
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_lname, token, sizeof(db_lname) - 1);
        db_lname[sizeof(db_lname) - 1] = '\0';

        // parse username
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        strncpy(db_uname, token, sizeof(db_uname) - 1);
        db_uname[sizeof(db_uname) - 1] = '\0';

        // parse password
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

        // print row
        printf("| %-15s | %-15s | %-15s | %-15s | $%-9.2f |\n", db_fname, db_lname, db_uname, db_pass, atof(db_balance));
    }
    // print bottom border
    printf("%s\n", border);
    fclose(fp);
}

void admin_session(Account *admin_account)
{
    char option[12];

    const char *admin_message = "~~~~~~~~~~~~~~~~~~\n[1] Check Vault\n[2] View Accounts\n[3] Transfer Funds\n[4] Log out\n~~~~~~~~~~~~~~~~~~\n";

    printf("Welcome back, Admin: %s %s\n", admin_account->fname, admin_account->lname);

    // user session loop
    while (1)
    {
        printf("%s\n", admin_message);
        printf("> ");

        if (!fgets(option, sizeof option, stdin))
        {
            printf("\nEOF received, exiting.");
            break;
        }

        // strip newline
        size_t len2 = strlen(option);
        if (len2 && option[len2 - 1] == '\n')
            option[len2 - 1] = '\0';

        // check for options (first character)
        switch (option[0])
        {
        case '1':
        {
            printf("The super secret vault contains $%.2f\n", admin_account->balance);
            break;
        }
        case '2':
        {
            printf("All user accounts:\n");
            print_accounts();
            break;
        }
        case '3':
            printf("Specify donor and recipient accounts:\n");
            break;
        case '4':
        {
            printf("Logging out...");
            return;
        }
        default:
        {
            printf("Unknown option. Please try again.");
            break;
        }
        }
    }
}

int main(void)
{
    char option[16];
    char userbuf[128];
    char passbuf[128];

    const char *welcome_message = "\nWelcome to Bank 656!\n~~~~~~~~~~~~~~~~~~~~\n[1] User Login\n[2] Admin Login\n[3] Exit\n~~~~~~~~~~~~~~~~~~~~";

    // main program loop
    while (1)
    {
        // print welcome message and options list
        printf("%s\n", welcome_message);
        printf("> ");
        if (!fgets(option, sizeof option, stdin))
        {
            puts("\nEOF received, exiting.");
            break;
        }

        // strip newline
        size_t len2 = strlen(option);
        if (len2 && option[len2 - 1] == '\n')
            option[len2 - 1] = '\0';

        // check for options (first character)
        switch (option[0])
        {
        case '1':
            if (get_creds(userbuf, passbuf) != 0)
            {
                printf("Error reading credentials, exiting...");
                return 1;
            }
            Account user_account; // allocate account on stack
            // pass in the account address
            if (authenticate("users.csv", userbuf, passbuf, &user_account))
            {
                // start user session
                user_session(&user_account);
                break;
            }
            else
            {
                printf("Invalid credentials, try again.");
            }
            break;
        case '2':
            if (get_creds(userbuf, passbuf) != 0)
            {
                printf("Error reading credentials, exiting...");
                return 1;
            }
            Account admin_account; // allocate account on stack
            // pass in the account address
            if (authenticate("admin.csv", userbuf, passbuf, &admin_account))
            {
                // start admin session
                admin_session(&admin_account);
                break;
            }
            else
            {
                printf("Invalid credentials, try again.");
            }
            break;
        case '3':
            puts("Goodbye.");
            return 0;
        default:
            puts("Unknown option.");
            break;
        }
    }

    return 0;
}