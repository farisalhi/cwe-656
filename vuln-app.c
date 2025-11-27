#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_USERS 128
#define MAX_ADMINS 10

// struct to contain account info
typedef struct
{
    char fname[128];
    char lname[128];
    char username[128];
    char password[128];
    double balance;
} Account;

int get_creds(char usernamebuf[], char passbuf[])
{
    // prompt for credentials first
    printf("Enter your credentials to access your bank account...\n");
    // ask for username
    printf("Username: ");

    if (!fgets(usernamebuf, 128, stdin))
    {
        puts("\nEOF received, exiting.");
        return 1;
    }

    size_t len = strlen(usernamebuf);
    if (len && usernamebuf[len - 1] == '\n')
        usernamebuf[len - 1] = '\0';

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

// function search through the given accounts list and find if the given username and password
// match that of any account in the list
int authenticate(char usernamebuf[], char passbuf[], Account *accounts_list, size_t account_count, Account *auth_account)
{
    int authenticated = 0;
    for (size_t i = 0; i < account_count; i++)
    {
        if (strcmp(accounts_list[i].username, usernamebuf) == 0 &&
            strcmp(accounts_list[i].password, passbuf) == 0)
        {
            if (auth_account)
            {
                *auth_account = accounts_list[i];
            }
            return 1;
        }
    }
    // No account matches
    return 0;
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
// initialize all the accounts in the given file and return the number of accounts
int init_accounts(const char *file, Account *accounts_list, size_t max_accounts)
{
    char line[256];
    size_t count = 0;

    // open users file
    FILE *fp = fopen(file, "r");
    if (!fp)
    {
        printf("error?\n");
        fprintf(stderr, "Error opening %s\n", file);
        return -1;
    }

    // scan through the file and fill the Account struct
    while (count < max_accounts && fgets(line, sizeof(line), fp))
    {
        // create a new account
        Account account;
        char *token;

        // strip newline
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n')
            line[l - 1] = '\0';

        // parse first name
        token = strtok(line, ",");
        if (!token)
            continue; // in case of empty lines
        // copy first name into the account
        strncpy(account.fname, token, sizeof(account.fname) - 1);
        account.fname[sizeof(account.fname) - 1] = '\0';

        // parse last name
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        // copy last name into account
        strncpy(account.lname, token, sizeof(account.lname) - 1);
        account.lname[sizeof(account.lname) - 1] = '\0';

        // parse username
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        // copy username into accounts
        strncpy(account.username, token, sizeof(account.username) - 1);
        account.username[sizeof(account.username) - 1] = '\0';

        // parse password
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        // copy password into account
        strncpy(account.password, token, sizeof(account.password) - 1);
        account.password[sizeof(account.password) - 1] = '\0';

        // parse balance
        token = strtok(NULL, ",");
        if (!token)
            continue; // in case of empty lines
        account.balance = atof(token);

        accounts_list[count++] = account;
    }
    fclose(fp);
    return (int)count;
}

// function to overwrite existing save file with new values
void save_to_file(const char *file, Account *accounts_list, size_t account_count)
{
    printf("Saving...\n");
    // open file
    FILE *fp = fopen(file, "w");
    if (!fp)
    {
        printf("error?\n");
        fprintf(stderr, "Error opening %s for writing\n", file);
        return;
    }

    for (size_t i = 0; i < account_count; ++i)
    {
        fprintf(fp, "%s,%s,%s,%s,%.2f\n",
                accounts_list[i].fname,
                accounts_list[i].lname,
                accounts_list[i].username,
                accounts_list[i].password,
                accounts_list[i].balance);
    }
    fclose(fp);
    printf("Saved to %s\n", file);
    return;
}

int print_accounts_by_row(Account *accounts_list, size_t accounts_list_count)
{
    // print each account
    for (size_t i = 0; i < accounts_list_count; i++)
    {
        printf("[%zu] %-15s %-15s %-15s %-20.2f\n", i, accounts_list[i].fname, accounts_list[i].lname, accounts_list[i].username, accounts_list[i].balance);
    }

    return accounts_list_count;
}
// print all accounts and their balances in a formatted table
void print_accounts_table(Account *accounts_list, size_t accounts_list_count)
{
    const char *border = "+-----------------+-----------------+-----------------+-----------------+----------------------+";

    // print table header
    printf("%s\n", border);
    printf("| %-15s | %-15s | %-15s | %-15s | %-20s |\n", "First Name", "Last Name", "Username", "Password", "Balance");
    printf("%s\n", border);

    // print each account
    for (size_t i = 0; i < accounts_list_count; i++)
    {
        printf("| %-15s | %-15s | %-15s | %-15s | %-20.2f |\n", accounts_list[i].fname, accounts_list[i].lname, accounts_list[i].username, accounts_list[i].password, accounts_list[i].balance);
    }

    // print bottom border
    printf("%s\n", border);
}

void transfer_funds_and_save_to_file(Account *user_accounts_list, size_t user_count, const char *user_file)
{
    char option[12];
    // initialize pointers to the accounts involved in the trasnfer
    Account *from_account = NULL;
    Account *to_account = NULL;

    while (1)
    {
        int rows = print_accounts_by_row(user_accounts_list, user_count);
        if (rows < 0)
            printf("Cannot have negative users.");

        // Ask for FROM account
        while (1)
        {
            printf("Which account would you like to transfer FROM? (q to exit).\n");
            printf("> ");
            if (!fgets(option, sizeof option, stdin))
            {
                printf("\nEOF received, exiting.");
                return;
            }
            // sanitize and validate option
            // strip newline
            size_t len1 = strlen(option);
            if (len1 && option[len1 - 1] == '\n')
                option[len1 - 1] = '\0';

            if (strcmp(option, "q") == 0 || strcmp(option, "Q") == 0)
                puts("Transfer cancelled.\n");
            return;

            // parse option to index and check bounds
            char *end = NULL;
            long idx = strtol(option, &end, 10);
            if (*option == '\0' || *end != '\0' || idx < 0 || (size_t)idx >= user_count)
            {
                puts("Invalid choice. Enter the number of one of the listed accounts.");
                continue;
            }

            from_account = &user_accounts_list[idx];
            break;
        }
        printf("Selected FROM account: %s %s (%s)\n", from_account->fname, from_account->lname, from_account->username);

        // Ask for TO account
        while (1)
        {
            printf("Which account would you like to transfer TO? (q to exit).\n");
            printf("> ");
            if (!fgets(option, sizeof option, stdin))
            {
                printf("\nEOF received, exiting.");
                return;
            }
            // sanitize and validate option
            // strip newline
            size_t len2 = strlen(option);
            if (len2 && option[len2 - 1] == '\n')
                option[len2 - 1] = '\0';

            if (strcmp(option, "q") == 0 || strcmp(option, "Q") == 0)
                puts("Transfer cancelled.\n");
            return;

            // parse option to index and check bounds
            char *end = NULL;
            long idx = strtol(option, &end, 10);
            if (*option == '\0' || *end != '\0' || idx < 0 || (size_t)idx >= user_count)
            {
                puts("Invalid choice. Enter the number of one of the listed accounts.");
                continue;
            }

            to_account = &user_accounts_list[idx];
            break;
        }
        printf("Selected TO account: %s %s (%s)\n", to_account->fname, to_account->lname, to_account->username);

        // Ask for HOW MUCH to transfer
        double amount;
        while (1)
        {
            printf("How much would you like to transfer? (q to exit).\n");
            printf(">");
            if (!fgets(option, sizeof option, stdin))
            {
                printf("\nEOF received, exiting.");
                return;
            }
            size_t len3 = strlen(option);
            if (len3 && option[len3 - 1] == '\n')
                option[len3 - 1] = '\0';

            if (strcmp(option, "q") == 0 || strcmp(option, "Q") == 0)
                puts("Transfer cancelled.\n");
            return;

            char *end = NULL;
            double value = strtod(option, &end);

            if (*option == '\0' || *end != '\0')
            {
                puts("Amount must be a valid number.");
                continue;
            }
            if (value <= 0)
            {
                puts("Amount must be positive.");
                continue;
            }

            if (value > from_account->balance)
            {
                puts("Amount exceeds the FROM account balance.");
                continue;
            }
            amount = value;
            break;
        }

        while (1)
        {
            printf("Transfer $%.2f from %s %s to %s %s? y/n\n", amount, from_account->fname, from_account->lname, to_account->fname, to_account->lname);
            printf("> ");
            if (!fgets(option, sizeof option, stdin))
            {
                printf("\nEOF received, exiting.");
                return;
            }
            // sanitize and validate option
            // strip newline
            size_t len4 = strlen(option);
            if (len4 && option[len4 - 1] == '\n')
                option[len4 - 1] = '\0';

            if (strcmp(option, "y") == 0 || strcmp(option, "Y") == 0)
            {
                break;
            }
            else if (strcmp(option, "n") == 0 || strcmp(option, "N") == 0)
            {
                puts("Transfer cancelled.\n");
                return;
            }
            else
            {
                puts("Invalid option. Please try again.");
            }
        }

        // transfer the funds
        from_account->balance = from_account->balance - amount;
        to_account->balance = to_account->balance + amount;

        puts("Transfer complete");
        // save updated values to file
        save_to_file(user_file, user_accounts_list, user_count);
        break;
    }
}

void admin_session(Account *admin_account, Account *user_accounts_list, size_t user_count, Account *admin_accounts_list, size_t admin_count, const char *user_file, const char *admin_file)
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
            printf("All USER accounts:\n");
            print_accounts_table(user_accounts_list, user_count);
            printf("All ADMIN accounts:\n");
            print_accounts_table(admin_accounts_list, admin_count);
            break;
        }
        case '3':
            transfer_funds_and_save_to_file(user_accounts_list, user_count, user_file);
            break;
        case '4':
        {
            printf("Logging out...");
            return;
        }
        default:
        {
            puts("Unknown option. Please try again.");
            break;
        }
        }
    }
}

int main(void)
{
    const char *USER_FILE = "users.csv";
    const char *ADMIN_FILE = "admins.csv";
    // initialize user and admin account struct lists
    Account user_accounts_list[MAX_USERS];
    Account admin_accounts_list[MAX_ADMINS];

    // structs to hold authenticated user or admin account
    Account user_account;
    Account admin_account;

    // read user file and create list of account structs
    int user_count = init_accounts(USER_FILE, user_accounts_list, MAX_USERS);
    if (user_count < 0)
        return 1;

    // read admin file and create list of account structs
    int admin_count = init_accounts(ADMIN_FILE, admin_accounts_list, MAX_ADMINS);
    if (admin_count < 0)
        return 1;

    char option[16];
    char usernamebuf[128];
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
            if (get_creds(usernamebuf, passbuf) != 0)
            {
                printf("Error reading credentials, exiting...");
                return 1;
            }
            // pass in the inputs and user accounts list
            if (authenticate(usernamebuf, passbuf, user_accounts_list, (size_t)user_count, &user_account))
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
            if (get_creds(usernamebuf, passbuf) != 0)
            {
                printf("Error reading credentials, exiting...");
                return 1;
            }
            // pass in the inputs and user accounts list
            if (authenticate(usernamebuf, passbuf, admin_accounts_list, (size_t)admin_count, &admin_account))
            {
                // start user session
                admin_session(&admin_account, user_accounts_list, (size_t)user_count, admin_accounts_list, admin_count, USER_FILE, ADMIN_FILE);
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
            puts("Invalid option. Please try again.");
            break;
        }
    }

    return 0;
}