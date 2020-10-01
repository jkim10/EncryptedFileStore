#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "./crypto/sha256.h"
#include "./crypto/aes.h"

char *xOr(char *a, char *b)
{
    char *result = malloc(sizeof(a) * (strlen(a) + 1));
    for (int i = 0; i < strlen(a); i++)
    {
        result[i] = (a[i] ^ b[i]);
    }
    return result;
}

BYTE *encrypt(char *text, BYTE *hPass)
{
    WORD key_schedule[60];
    BYTE *enc_buf = malloc(128);
    aes_key_setup(hPass, key_schedule, 256);
    aes_encrypt((BYTE *)text, enc_buf, key_schedule, 256);
    return enc_buf;
}

size_t encrypt_cbc(char *fileName, FILE *archive, BYTE *hPass)
{
    FILE *fp = fopen(fileName, "rb");
    FILE *urand = fopen("/dev/urandom", "r");
    char m_prev[16];
    size_t num_of_bytes = 0;
    fread(&m_prev, 1, 16, urand);
    fclose(urand);
    if (fp)
    {
        fwrite(m_prev, 16, 1, archive);
        int read = 0;
        char buffer[16];
        while ((read = fread(buffer, 16, 1, fp)) > 0)
        {
            BYTE *encrypted_buffer = encrypt(xOr(buffer, m_prev), hPass);
            size_t bytesWritten = fwrite(encrypted_buffer, 1, 16, archive);
            strcpy(m_prev, (char *)encrypted_buffer);
            memset(buffer, 0, sizeof buffer);
            num_of_bytes += bytesWritten;
        }
        return num_of_bytes;
    }
    else
    {
        printf("The file `%s` was not found and will be skipped.\n", fileName);
    }
    return num_of_bytes;
}

BYTE *decrypt(BYTE *cipher, BYTE *hPass)
{
    WORD key_schedule[60];
    BYTE *enc_buf = malloc(128);
    aes_key_setup(hPass, key_schedule, 256);
    aes_decrypt(cipher, enc_buf, key_schedule, 256);
    return enc_buf;
}

BYTE *hashPassword(char *password, int numberOfIterations)
{
    BYTE *buf = malloc(SHA256_BLOCK_SIZE);
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE *)password, strlen(password));
    sha256_final(&ctx, buf);
    for (int i = 1; i < numberOfIterations; i++)
    {
        sha256_init(&ctx);
        sha256_update(&ctx, buf, strlen((char *)buf));
        sha256_final(&ctx, buf);
    }
    return buf;
}

void print_hex(BYTE str[], int len)
{
    int idx;

    for (idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

int main(int argc, char *argv[])
{
    //Default (assumes password included)
    char *password;
    int includedPass = 0;
    char *archiveName = argv[2];
    int firstFile = 3;

    if (argc < 3)
    {
        printf("Usage: 'cstore [command] [-p password] archivename file1 file2 file3] \n");
        return 0;
    }

    // INTO LIST COMMMAND
    if (strcmp(argv[1], "list") == 0)
    {
        printf("LIST\n");
        return 0;
    }

    // Check for Password Option
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            includedPass = 1;
            if (argc > (i + 1))
            {
                password = argv[i + 1];
                firstFile = firstFile + 2;
                archiveName = argv[4];
            }
            else
            {
                printf("No password provided\n");
                return 0;
            }
            break;
        }
    }

    // Get password if none given
    if (!includedPass)
    {
        password = getpass("Password: ");
    }

    // Hash password
    BYTE *hPass = hashPassword(password, 10000);

    // PASSWORD PROTECTED FUNCTIONS
    if (strcmp(argv[1], "add") == 0)
    {
        FILE *archive = fopen(archiveName, "ab+");
        for (int i = firstFile; i < argc; i++)
        {
            char fileName[100];
            memset(fileName, '\0', 100);
            memcpy(fileName, argv[i], strlen(argv[i]) + 1);
            int enc_file_size = encrypt_cbc(fileName, archive, hPass);
            FILE *temp = tmpfile();
            if (temp)
            {
                fprintf(temp, "Hello, Temp!");
            }
            char c;
            c = fgetc(temp);
            while (c != EOF)
            {
                printf("%c", c);
                c = fgetc(temp);
            }
            if (enc_file_size > 0)
            {
                fwrite(fileName, 100, 1, archive);
            };
        }
        fclose(archive);
    }
    else if (strcmp(argv[1], "extract") == 0)
    {
        FILE *archive = fopen(archiveName, "r");
        if (archive)
        {
            char buffer[16];
            for (int i = firstFile; i < argc - 1; i++)
            {
                while (fgets(buffer, 16, archive) != NULL)
                {
                    printf(argv[i], "%s", buffer);
                }
            }
        }
        else
        {
            printf("The archive `%s` was not found\n", archiveName);
        }
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
    }
    else
    {
        printf("%s is not a valid option. Try one of the following [list, add, extract, delete]\n", argv[1]);
    }
    if (!includedPass)
    {
        free(password);
    }
    free(hPass);
    return 0;
}