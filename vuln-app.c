#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef ADMIN_AES_KEY
#define ADMIN_AES_KEY ""
#endif

#define MAX_USERS 128
#define MAX_ADMINS 10
#define CONFIG_FILE "./tmp/.bank/.cache/config.cfg"

// struct to contain account info
typedef struct
{
    char fname[128];
    char lname[128];
    char username[128];
    char password[128];
    double balance;
} Account;

// return the admin aes encryption key hardcoded into the env variable
// if env variable is unset, fallback to empty string -> admin console won't work
static const char *load_admin_aes_key(void)
{
    const char *env_key = getenv("ADMIN_AES_KEY");
    if (env_key && env_key[0] != '\0')
    {
        return env_key;
    }
    // env not set
    if (ADMIN_AES_KEY[0] != '\0')
    {
        return ADMIN_AES_KEY;
    }

    return "";
}

// helper function to convert a hex string to binary representation
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{

    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2)
    {
        return -1;
    }

    for (size_t i = 0; i < out_len; ++i)
    {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%02x", &byte) != 1)
        {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return 0;
}

// helper to convert bytes back to hex
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_out)
{
    for (size_t i = 0; i < len; ++i)
    {
        sprintf(hex_out + (i * 2), "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

// reads the encrypted admins.enc file to output buffer using the AES key
// AES uses CBC (cipher block chaining)
// needs block of random bytes (initialization vector IV) to act as a seed
// ensures encrypting the same plaintext twice with the same key does not
// give the same result
// better to use this than ECB
/* inputs:
- path to admins.enc
- admin aes encryption key and length
- pointer to output buffer and placeholder for length (to be determined later)
*/
static int decrypt_file_to_buffer(const char *file, const unsigned char *key, unsigned char **plaintext, size_t *plaintext_len)
{
    // open the given file in binary mode
    FILE *fp = fopen(file, "rb");
    if (!fp)
    {
        fprintf(stderr, "Failed to open %s for reading.\n", file);
        return -1;
    }

    // seek to end of file (for determining length)
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return -1;
    }
    // ftell returns total bytes from start to end
    long total_len = ftell(fp);
    if (total_len < 0)
    {
        fclose(fp);
        return -1;
    }
    rewind(fp); // return to start of file

    // encrypted blob (binary large object) must be at least 16 bytes
    // IV required for AES-CBC must be exactly 16 bytes
    if (total_len < 16)
    {
        fclose(fp);
        fprintf(stderr, "Encrypted file %s is too small to contain an IV.\n", file);
        return -1;
    }

    // allocate a buffer for entire file
    unsigned char *cipher_blob = malloc((size_t)total_len);
    if (!cipher_blob)
    {
        fclose(fp);
        return -1;
    }

    // read entire file and free/return in case of not enough bytes read
    size_t read_len = fread(cipher_blob, 1, (size_t)total_len, fp);
    fclose(fp);
    if (read_len != (size_t)total_len)
    {
        free(cipher_blob);
        return -1;
    }

    // first 16 bytes of cipher blob are the IV used for AES-CBC
    unsigned char iv[16];
    // copy iv to buffer
    memcpy(iv, cipher_blob, sizeof iv);
    // rest of file is ciphertext contain admin creds
    unsigned char *ciphertext = cipher_blob + sizeof iv;
    size_t ciphertext_len = (size_t)total_len - sizeof iv;

    // allocate openssl cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        free(cipher_blob);
        return -1;
    }

    // allocate big enough buffer for decrypted plaintext
    unsigned char *plain = malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    if (!plain)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(cipher_blob);
        return -1;
    }

    int len = 0;
    int total_plain = 0;

    // configure AES-CBC context using the key and iv
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(cipher_blob);
        free(plain);
        return -1;
    }

    // decrypt ciphertext into plaintext
    // collect number of bytes decrypted
    if (!EVP_DecryptUpdate(ctx, plain, &len, ciphertext, (int)ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(cipher_blob);
        free(plain);
        return -1;
    }
    total_plain += len;

    // finalize decryption with padding checks and authentication
    if (!EVP_DecryptFinal_ex(ctx, plain + total_plain, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        free(cipher_blob);
        free(plain);
        return -1;
    }
    total_plain += len;

    // null-terminate so we can use in csv
    plain[total_plain] = '\0';

    // fill pointer to painttext buffer
    *plaintext = plain;
    *plaintext_len = (size_t)total_plain;

    // cleanup
    EVP_CIPHER_CTX_free(ctx);
    free(cipher_blob);
    return 0;
}

// helper to parse an admin csv line (includes the password)
// takes a pointer to an account struct and fills in the values
static int parse_admin_csv_line(char *line, Account *account)
{
    char *saveptr = NULL;
    // first name
    char *token = strtok_r(line, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->fname, token, sizeof(account->fname) - 1);
    account->fname[sizeof(account->fname) - 1] = '\0';

    // last name
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->lname, token, sizeof(account->lname) - 1);
    account->lname[sizeof(account->lname) - 1] = '\0';

    // username
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->username, token, sizeof(account->username) - 1);
    account->username[sizeof(account->username) - 1] = '\0';

    // password
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->password, token, sizeof(account->password) - 1);
    account->password[sizeof(account->password) - 1] = '\0';

    // balance
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    account->balance = atof(token);

    return 1;
}

// helper to parse a USER csv line (does NOT include the password)
// password needs to be loaded from config file
// takes a pointer to an account struct and fills in the values
static int parse_user_csv_line(char *line, Account *account)
{
    char *saveptr = NULL;
    // first name
    char *token = strtok_r(line, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->fname, token, sizeof(account->fname) - 1);
    account->fname[sizeof(account->fname) - 1] = '\0';

    // last name
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->lname, token, sizeof(account->lname) - 1);
    account->lname[sizeof(account->lname) - 1] = '\0';

    // username
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    strncpy(account->username, token, sizeof(account->username) - 1);
    account->username[sizeof(account->username) - 1] = '\0';

    // password is stored in config file
    // initialize to empty for now
    account->password[0] = '\0';

    // balance
    token = strtok_r(NULL, ",", &saveptr);
    if (!token)
        return 0;
    account->balance = atof(token);

    return 1;
}

// helper to load user passwords from config and merge into accounts list
static void load_user_passwords(Account *accounts_list, size_t count)
{
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp)
        return;

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n')
            line[len - 1] = '\0';

        // parse username,password
        char *comma = strchr(line, ',');
        if (!comma)
            continue; // skip anything else (aka, the aes key)

        *comma = '\0';
        char *cfg_user = line;
        char *cfg_pass = comma + 1;

        // find user in the list and update the password
        for (size_t i = 0; i < count; i++)
        {
            // check if the usernames are the same
            if (strcmp(accounts_list[i].username, cfg_user) == 0)
            {
                // if so, copy the password into the password field in the accoun struct
                strncpy(accounts_list[i].password, cfg_pass, sizeof(accounts_list[i].password) - 1);
                accounts_list[i].password[sizeof(accounts_list[i].password) - 1] = '\0';
                break;
            }
        }
    }
    fclose(fp);
}

// gets the inputed username and password credentials from the command line
int get_creds(char usernamebuf[], char passbuf[])
{
    // prompt for credentials
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

// search through the given accounts list and find if the given username and password
// match that of any account in the list
int authenticate(char usernamebuf[], char passbuf[], Account *accounts_list, size_t account_count, Account *auth_account)
{
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

// basic user session
// can only check balance
// TODO: transfer from personal account only
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
// these accounts are not encrypted -> basic user accounts
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
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n')
            line[l - 1] = '\0';

        if (!parse_user_csv_line(line, &accounts_list[count]))
            continue;

        count++;
    }
    fclose(fp);

    // load the passwords from the config file
    load_user_passwords(accounts_list, count);

    return (int)count;
}

// initialize the admin accounts saved in encrypted admins file
static int init_encrypted_accounts(const char *file, const char *key_hex, Account *accounts_list, size_t max_accounts)
{
    unsigned char key[32];
    // convert the admin aes key to binary
    if (hex_to_bytes(key_hex, key, sizeof key) != 0)
    {
        fputs("ADMIN_AES_KEY must be a 64-character hex string (256-bit key).\n", stderr);
        return -1;
    }

    // attempt to decrypt the file using the key
    // decrypt to plantext
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    // decrypt failed
    // environment variable key is incorrect
    if (decrypt_file_to_buffer(file, key, &plaintext, &plaintext_len) != 0)
    {
        puts("Failed to decrypt admin file. The key is incorrect.\n");
        return -1;
    }

    // parse the file to retrieve the admin accounts
    size_t count = 0;
    char *saveptr = NULL;
    char *line = strtok_r((char *)plaintext, "\n", &saveptr);
    while (line && count < max_accounts)
    {
        // use the admin parser (includes the password)
        if (parse_admin_csv_line(line, &accounts_list[count]))
        {
            count++;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(plaintext);
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
        fprintf(fp, "%s,%s,%s,%.2f\n",
                accounts_list[i].fname,
                accounts_list[i].lname,
                accounts_list[i].username,
                accounts_list[i].balance);
    }
    fclose(fp);
    printf("Saved to %s\n", file);
    return;
}
// print accounts row-by-row and return the number of rows
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

// allows an admin to transfer funds from any account to any account
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
            {
                puts("Transfer cancelled.\n");
                return;
            }

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
            {
                puts("Transfer cancelled.\n");
                return;
            }

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
            {
                puts("Transfer cancelled.\n");
                return;
            }

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

// authenticated admin session
// can only be accessed by an admin
void admin_session(Account *admin_account, Account *user_accounts_list, size_t user_count, Account *admin_accounts_list, size_t admin_count, const char *user_file)
{
    char option[12];

    const char *admin_message = "~~~~~~~~~~~~~~~~~~\n[1] Check Vault\n[2] View User Accounts\n[3] View Admin Accounts\n[4] Transfer Funds\n[5] Log out\n~~~~~~~~~~~~~~~~~~\n";

    printf("Welcome back, Admin: %s %s\n", admin_account->fname, admin_account->lname);

    // admin session loop
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
            break;
        }
        case '3':
        {
            printf("All ADMIN accounts:\n");
            print_accounts_table(admin_accounts_list, admin_count);
            break;
        }
        case '4':
        {
            transfer_funds_and_save_to_file(user_accounts_list, user_count, user_file);
            break;
        }
        case '5':
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

void debug_panel(void)
{
    char option[256];
    int stage = 0;
    time_t last_hint_time = 0;
    printf("--- DEBUG PANEL ---\n");
    // scare the user a little
    printf("Authorized Personnel Only. Violators will be logged.\n");
    while (1)
    {
        printf("#> ");
        if (!fgets(option, sizeof option, stdin))
        {
            puts("\nEOF received, exiting.");
            break;
        }

        // strip newline
        size_t len = strlen(option);
        if (len && option[len - 1] == '\n')
            option[len - 1] = '\0';

        // Layer 1
        // user must input commands in correct sequence
        // if command sequence isn't correct, dump fake diagnostics to confuse them
        bool is_valid_command = false;

        // wait for "help" command
        if (stage == 0)
        {
            if (strcmp(option, "help") == 0)
            {
                printf("Available commands: [status] [exit] [diagnose] [flush]\n");
                stage = 1;
                is_valid_command = true;
            }
            else if (strcmp(option, "exit") == 0)
            {
                return;
            }
        }
        else if (stage == 1)
        {
            if (strcmp(option, "status --dump") == 0)
            {
                printf("Dumping core memory...\n");
                printf("0x00400000: 55 48 89 e5 48 83 ec 20\n");
                printf("0x00400008: c7 45 fc 00 00 00 00 48\n");
                printf("[HINT]: Sesame protocol active for 3 seconds.\n");

                // start the timer now
                last_hint_time = time(NULL);
                stage = 2;
                is_valid_command = true;
            }
            else if (strcmp(option, "help") == 0)
            {
                // stay on stage 1 but print help
                printf("Available commands: [status] [exit] [diagnose] [flush]\n");
                is_valid_command = true;
            }
        }
        // waiting for open sesame (time sensitive)
        else if (stage == 2)
        {
            if (strcmp(option, "open sesame") == 0)
            {
                time_t now = time(NULL);
                // check if entered within 3 seconds
                if (difftime(now, last_hint_time) <= 3.0)
                {
                    printf("Protocol Accepted.\n");
                    printf("Enter Magic Token to decrypt storage:\n");
                    stage = 3;
                    is_valid_command = true;
                }
                else
                {
                    printf("[ERROR] Protocol Timeout. Session Reset.\n");
                    stage = 0; // Reset to beginning
                    is_valid_command = true;
                }
            }
        }
        // wait for magic token
        else if (stage == 3)
        {
            if (strcmp(option, "!dev_override!") == 0)
            {
                printf("Token Accepted. Decrypting config storage...\n");
                // now we can read the config file and present the aes key
                FILE *fp = fopen(CONFIG_FILE, "r");
                if (!fp)
                {
                    printf("config file not found at %s\n", CONFIG_FILE);
                    return;
                }

                char line[256];
                while (fgets(line, sizeof(line), fp))
                {
                    // search for the key (after 14 chars)
                    if (strncmp(line, "ADMIN_AES_KEY=", 14) == 0)
                    {
                        char *encoded_hex = line + 14;
                        // strip newline
                        size_t keylen = strlen(encoded_hex);
                        if (keylen && encoded_hex[keylen - 1] == '\n')
                            encoded_hex[keylen - 1] = '\0';

                        // convert hex string from config to raw bytes
                        unsigned char encoded_bytes[32];
                        if (hex_to_bytes(encoded_hex, encoded_bytes, 32) != 0)
                        {
                            printf("Error: Config key is not valid hex.\n");
                            return;
                        }

                        // XOR with 0xDEADBEEF (repeated)
                        unsigned char xor_key[] = {0xDE, 0xAD, 0xBE, 0xEF};
                        unsigned char decoded_bytes[32];
                        for (int i = 0; i < 32; i++)
                        {
                            decoded_bytes[i] = encoded_bytes[i] ^ xor_key[i % 4];
                        }

                        // decode back to hex to print
                        char decoded_hex[65];
                        bytes_to_hex(decoded_bytes, 32, decoded_hex);

                        printf(">> DECODING SUCCESSFUL.\n");
                        printf("Admin credentials:\n");
                        printf("username:admin\npassword:password\n");
                        printf("deadbeef=%s\n", decoded_hex);
                    }
                }
                fclose(fp);
                return;
            }
            else
            {
                printf("[ERROR] Invalid Token. Security Alert Triggered.\n");
                printf("YOU SHOULDN'T BE HERE.\n");
                stage = 0; // Reset
                is_valid_command = true;
            }
        }
        // in case of invalid commands, generate random crap noise to confuse user
        if (!is_valid_command)
        {
            // Reset stage on bad input to make it harder to guess
            if (stage > 0)
            {
                stage = 0;
                printf("[SYSTEM] Sequence violation. Resetting state.\n");
            }

            // Print fake diagnostics
            int r = rand() % 4;
            if (r == 0)
                printf("[WARN] Heap fragmentation at 45%%\n");
            else if (r == 1)
                printf("[INFO] Garbage collection cycle started\n");
            else if (r == 2)
                printf("[ERR] Socket 443 connection refused\n");
            else
                // a cheeky little hint
                printf("Unknown command. Type 'help' for list.\n");
        }
    }
}

void change_password(Account *user_accounts_list, size_t user_count)
{
    char username[128];
    char old_pass[128];
    char new_pass[128];
    // random number between 15 and 30
    // the number of times user needs to hit enter before debug appears
    int target_enters = (rand() % 16) + 15;
    int count = 0;

    printf("--- Password Reset Portal ---\n");
    while (1)
    {
        printf("Enter your username: ");

        if (!fgets(username, sizeof(username), stdin))
            return;
        size_t len = strlen(username);
        if (len && username[len - 1] == '\n')
            username[len - 1] = '\0';
        // if they press enter, continue and count how many times
        if (username[0] == '\0')
        {
            count++;
            // obscure developer backdoor entry
            if (count == target_enters)
            {
                debug_panel();
                count = 0;
                return;
            }
            continue;
        }
        break;
    }
    // Normal change password logic
    printf("Enter old password: ");
    if (!fgets(old_pass, sizeof(old_pass), stdin))
        return;
    size_t len_old = strlen(old_pass);
    if (len_old && old_pass[len_old - 1] == '\n')
        old_pass[len_old - 1] = '\0';

    printf("Enter new password: ");
    if (!fgets(new_pass, sizeof(new_pass), stdin))
        return;
    size_t len_new = strlen(new_pass);
    if (len_new && new_pass[len_new - 1] == '\n')
        new_pass[len_new - 1] = '\0';

    // update config file containing user passwords
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp)
    {
        printf("config file not found at %s\n", CONFIG_FILE);
        return;
    }

    // write to temp file then copy to config
    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "%s.temp", CONFIG_FILE);
    FILE *fp_temp = fopen(temp_path, "w");
    if (!fp_temp)
    {
        fclose(fp);
        return;
    }

    char line[256];
    bool found = false;
    bool authenticated = false;

    while (fgets(line, sizeof(line), fp))
    {
        char line_cpy[256];
        strcpy(line_cpy, line);
        size_t len = strlen(line_cpy);
        if (len && line_cpy[len - 1] == '\n')
            line_cpy[len - 1] = '\0';

        // parse username, password
        char *comma = strchr(line_cpy, ',');
        if (comma)
        {
            *comma = '\0';
            // is the username the same?
            if (strcmp(username, line_cpy) == 0)
            {
                found = true;
                // is the old password the same?
                if (strcmp(old_pass, comma + 1) == 0)
                {
                    authenticated = true;
                    // write the updated password to the temp file
                    fprintf(fp_temp, "%s,%s\n", username, new_pass);
                }
                else
                {
                    // otherwise simply copy it to temp
                    fputs(line, fp_temp);
                }
            }
            else
            {
                fputs(line, fp_temp);
            }
        }
        else
        {
            fputs(line, fp_temp);
        }
    }
    fclose(fp);
    fclose(fp_temp);

    if (!found)
    {
        remove(temp_path);
        printf("User %s not found.\n", username);
        return;
    }
    if (!authenticated)
    {
        remove(temp_path);
        printf("Old password is not correct.\n");
        return;
    }
    // remove the old config file and rename with the updated one
    remove(CONFIG_FILE);
    rename(temp_path, CONFIG_FILE);

    // update the user accounts list
    for (size_t i = 0; i < user_count; i++)
    {
        if (strcmp(user_accounts_list[i].username, username) == 0)
        {
            strncpy(user_accounts_list[i].password, new_pass, sizeof(user_accounts_list[i].password) - 1);
            user_accounts_list[i].password[sizeof(user_accounts_list[i].password) - 1] = '\0';
            break;
        }
    }

    printf("Your password has been successfully changed.\n");
}

// main driver
int main(void)
{
    // seed random number generator for use in change_password
    srand(time(NULL));

    const char *USER_FILE = "users.csv";
    const char *ADMIN_FILE = "admins.enc";

    // get the admin key from env variable
    // or empty if none provided
    const char *admin_key = load_admin_aes_key();
    // admin key must be loaded from environment variable
    // in order to acces admin console
    bool admin_key_loaded = admin_key && admin_key[0] != '\0';
    // initialize user and admin account struct lists
    Account user_accounts_list[MAX_USERS];
    Account admin_accounts_list[MAX_ADMINS];

    // initialiaze authenticated user or admin account
    Account user_account;
    Account admin_account;

    int admin_count = 0;
    // read user file and create list of account structs
    int user_count = init_accounts(USER_FILE, user_accounts_list, MAX_USERS);
    if (user_count < 0)
        return 1;

    char option[16];
    char usernamebuf[128];
    char passbuf[128];

    const char *welcome_message = "Welcome to Bank 656!\n~~~~~~~~~~~~~~~~~~~~\n[1] User Login\n[2] Admin Login\n[3] Change Password\n[4] Exit\n~~~~~~~~~~~~~~~~~~~~";

    // main program loop
    while (1)
    {
        // reload the key status every iteration.
        admin_key = load_admin_aes_key();
        admin_key_loaded = admin_key && admin_key[0] != '\0';

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
                puts("Invalid credentials, try again.");
            }
            break;

        case '2':
            // the key must exactly match the key used to encrypt admins.csv
            // check if key is non-empty string
            if (admin_key_loaded)
            {
                admin_count = init_encrypted_accounts(ADMIN_FILE, admin_key, admin_accounts_list, MAX_ADMINS);

                // if init_encrypted_accounts returns an error, it likely means
                // the key was incorrect
                if (admin_count < 0)
                {
                    admin_key_loaded = false;
                    puts("Admin console unavailable. You are not authorized.");
                    break;
                }
            }
            else
            {
                // "accidental" debug statement reveals the name of the environment variable
                puts("DEBUG (delete me!): ADMIN_AES_KEY not loaded.");
                break;
            }

            if (get_creds(usernamebuf, passbuf) != 0)
            {
                printf("Error reading credentials, exiting...");
                return 1;
            }
            // pass in the inputs and user accounts list
            if (authenticate(usernamebuf, passbuf, admin_accounts_list, (size_t)admin_count, &admin_account))
            {
                // start user session
                admin_session(&admin_account, user_accounts_list, (size_t)user_count, admin_accounts_list, admin_count, USER_FILE);
                break;
            }
            else
            {
                printf("Invalid credentials, try again.\n");
            }
            break;
        case '3':
        {
            change_password(user_accounts_list, user_count);
            break;
        }
        case '4':
        {
            puts("Goodbye.");
            return 0;
        }
        default:
            puts("Invalid option. Please try again.");
            break;
        }
    }

    return 0;
}
