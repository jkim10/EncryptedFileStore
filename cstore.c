#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "./crypto/sha256.h"
#include "./crypto/aes.h"
#include <string.h>

void doXor(const BYTE in[], BYTE out[], size_t len)
{
    size_t idx;

    for (idx = 0; idx < len; idx++)
    {
        out[idx] ^= in[idx];
    }
}

int encrypt_cbc(FILE *fp, FILE *tmp, BYTE *hPass)
{
    FILE *urand = fopen("/dev/urandom", "rb");
    BYTE m_prev[16];
    fread(m_prev, 16, 1, urand);
    fclose(urand);
    if (fp)
    {
        fwrite(m_prev, 16, 1, tmp);
        int read = 0;
        BYTE buffer[16];
        while ((read = fread(buffer, 1, 16, fp)) > 0)
        {
            if (read < 16)
            {
                memset(buffer + read, 0, sizeof(buffer) - read);
            }
            doXor(buffer, m_prev, 16);
            WORD key_schedule[60];
            BYTE *enc_buf = (BYTE *)malloc(16);
            aes_key_setup(hPass, key_schedule, 256);
            aes_encrypt(m_prev, enc_buf, key_schedule, 256);
            fwrite(enc_buf, 1, 16, tmp);
            memcpy(m_prev, enc_buf, 16);
            memset(buffer, 0, 16);
            free(enc_buf);
        }
        fseek(fp, 0, SEEK_END);
        int fileSize = ftell(fp);
        fclose(fp);
        return fileSize;
    }
    else
    {
        printf("The file was not found and will be skipped.\n");
        return -1;
    }
}

BYTE *decrypt(BYTE *cipher, BYTE *hPass)
{
    WORD key_schedule[60];
    BYTE *enc_buf = malloc(16);
    aes_key_setup(hPass, key_schedule, 256);
    aes_decrypt(cipher, enc_buf, key_schedule, 256);
    return enc_buf;
}

void decrypt_cbc(FILE *cipherText, BYTE *hPass, FILE *newFile, int fileSize, int numBlocks)
{
    BYTE m_prev[16];
    int fileSizeCpy = fileSize;
    BYTE buffer[16];
    fread(m_prev, 16, 1, cipherText);
    int padding = ((numBlocks * 16) - 16 - fileSize);
    for (int i = 0; i < (numBlocks - 1); i++)
    {
        fread(buffer, 1, 16, cipherText);
        int writeSize = 16;
        if (fileSizeCpy < 16)
        {
            writeSize = 16 - padding;
        }
        BYTE *decrypted = decrypt((BYTE *)buffer, hPass);
        doXor(decrypted, m_prev, 16);
        int bytesWritten = fwrite(m_prev, 1, writeSize, newFile);
        memcpy(m_prev, buffer, 16);
        fileSizeCpy -= bytesWritten;
        free(decrypted);
    }
}
BYTE *calculateHMAC(BYTE *cipherText, size_t cipherSize, BYTE *hPass)
{
    BYTE *hMac = malloc(SHA256_BLOCK_SIZE);
    BYTE opad[32] = {0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};
    BYTE ipad[32] = {0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36};
    doXor(hPass, ipad, 32);
    BYTE *sndArg = malloc(32 + cipherSize);
    memcpy(sndArg, ipad, 32);
    memcpy(sndArg + 32, cipherText, cipherSize);
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, sndArg, (32 + SHA256_BLOCK_SIZE)); //H(K XOR ipad, text)
    sha256_final(&ctx, hMac);

    doXor(hPass, opad, 32);
    BYTE *fstArg = malloc(32 + SHA256_BLOCK_SIZE);
    memcpy(fstArg, opad, 32);
    memcpy(fstArg + 32, hPass, SHA256_BLOCK_SIZE);
    BYTE *concatenated = malloc(32 + (SHA256_BLOCK_SIZE * 2));
    memcpy(concatenated, fstArg, (32 + SHA256_BLOCK_SIZE));
    memcpy(concatenated + (32 + SHA256_BLOCK_SIZE), hMac, SHA256_BLOCK_SIZE);
    sha256_init(&ctx);
    sha256_update(&ctx, concatenated, (32 + (SHA256_BLOCK_SIZE * 2)));
    sha256_final(&ctx, hMac);
    free(sndArg);
    free(fstArg);
    free(concatenated);
    return hMac;
}
// Appends encrypted file with headers
void appendFile(FILE *src, char *fn, size_t fileSize, int numBlocks, FILE *dest)
{
    BYTE fileName[100];
    BYTE fileSizeStr[12];
    BYTE numBlocksStr[12];
    fseek(dest, -1, SEEK_END);
    rewind(src);
    memset(fileName, '\0', 100);
    memcpy(fileName, fn, strlen(fn));
    memset(fileSizeStr, '\0', 12);
    memset(numBlocksStr, '\0', 12);
    char fileSizeStrCpy[13];
    char numBlocksStrCpy[13];
    sprintf(fileSizeStrCpy, "%ld", fileSize);
    sprintf(numBlocksStrCpy, "%d", numBlocks);
    memcpy(fileSizeStr, fileSizeStrCpy, 12);
    memcpy(numBlocksStr, numBlocksStrCpy, 12);
    memset(fileSizeStr + strlen(fileSizeStrCpy), '\0', 12 - strlen(fileSizeStrCpy));
    memset(numBlocksStr + strlen(numBlocksStrCpy), '\0', 12 - strlen(numBlocksStrCpy));
    fwrite(fileName, 100, 1, dest);
    fwrite(fileSizeStr, 1, 12, dest);
    fwrite(numBlocksStr, 1, 12, dest);
    BYTE buff[1];
    int read = 0;
    rewind(src);
    while ((read = fread(buff, 1, 1, src) > 0))
    {
        fwrite(buff, 1, read, dest);
    }
}

void appendHMAC(FILE *file, BYTE *hPass)
{
    fseek(file, 0, SEEK_END);
    size_t archiveSize = ftell(file);
    rewind(file);
    BYTE *text = malloc(archiveSize);
    fread(text, 1, archiveSize, file);
    BYTE hMac[32];
    BYTE *calculatedHMAC = calculateHMAC(text, archiveSize, hPass);
    memcpy(hMac, calculatedHMAC, 32);
    FILE *tmp = tmpfile();
    fwrite(hMac, 32, 1, tmp);
    char name[100];
    memset(name, '\0', 100);
    memcpy(name, "hMac", 4);
    rewind(tmp);
    appendFile(tmp, name, 32, 2, file);
    fclose(tmp);
    free(text);
    free(calculatedHMAC);
}

void removeHMAC(FILE *file)
{
    fseeko(file, -156, SEEK_END);
    off_t position = ftello(file);
    ftruncate(fileno(file), position);
}

int authenticateHMAC(FILE *file, BYTE *hPass)
{
    BYTE fileHMAC[32];
    fseek(file, -32, SEEK_END);
    fread(fileHMAC, 32, 1, file);
    long int startHMAC = ftell(file);
    rewind(file);
    BYTE *noHmac = malloc(startHMAC);
    fread(noHmac, startHMAC, 1, file);
    BYTE newHMAC[32];
    BYTE *calculatedHMAC = calculateHMAC(noHmac, startHMAC, hPass);
    memcpy(newHMAC, calculatedHMAC, 32);
    int isEqual = memcmp(fileHMAC, newHMAC, 32);
    free(noHmac);
    free(calculatedHMAC);
    if (isEqual == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

BYTE *hashPassword(BYTE *password, int numberOfIterations)
{
    BYTE *buf = malloc(SHA256_BLOCK_SIZE);
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE *)password, strlen((char *)password));
    sha256_final(&ctx, buf);
    for (int i = 1; i < numberOfIterations; i++)
    {
        sha256_init(&ctx);
        sha256_update(&ctx, buf, sizeof(buf));
        sha256_final(&ctx, buf);
    }
    return buf;
}
char *getFileName(char *path)
{
    char *last = strrchr(path, '/');
    if (last != NULL)
    {
        last++;
        return last;
    }
    else
    {
        return path;
    }
}
int main(int argc, char *argv[])
{
    //Default (assumes password included)
    BYTE *password;
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
        FILE *archive = fopen(archiveName, "rb");
        if (archive)
        {
            fseek(archive, 0, SEEK_END);
            size_t archiveSize = ftell(archive);
            rewind(archive);
            printf("Files in %s:\n", archiveName);
            char fileName[100];
            char fileSizeStr[12];
            char numBlocksStr[12];
            int stopPoint = archiveSize - 32 - 124; // 32 is the HMAC and 124 is the HMAC HEADER
            while ((ftell(archive) != stopPoint) && (fread(fileName, 100, 1, archive) > 0))
            {
                if (ftell(archive) == (archiveSize - 32 - 124)) // SKIPPING LAST ENTRY FOR HMAC
                {
                    break;
                }
                fread(fileSizeStr, 12, 1, archive);
                fread(numBlocksStr, 12, 1, archive);
                int offset = (atoi(numBlocksStr) * 16);
                printf("- %s\n", fileName);
                fseek(archive, offset, SEEK_CUR);
            }

            fclose(archive);
        }
        else
        {
            printf("The archive %s does not exist", archiveName);
        }
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
                password = (BYTE *)argv[i + 1];
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
        password = (BYTE *)getpass("Password: ");
    }

    // Hash password
    BYTE *hPass = hashPassword(password, 10000);

    //Check if archive exists
    int archiveExists = 1;
    FILE *readArchive = fopen(archiveName, "r");
    if (readArchive)
    {
        if (!authenticateHMAC(readArchive, hPass))
        {
            printf("WRONG PASSWORD OR FILE HAS BEEN TAMPERED WITH.\n");
            fclose(readArchive);
            free(hPass);
            return 0;
        }
        fclose(readArchive);
    }
    else
    {
        archiveExists = 0;
    }

    // PASSWORD PROTECTED FUNCTIONS
    if (strcmp(argv[1], "add") == 0)
    {

        FILE *archive = fopen(archiveName, "ab+");
        removeHMAC(archive);
        rewind(archive);
        if (!archiveExists)
        {
            printf("Archive %s has been created\n", archiveName);
        }
        for (int i = firstFile; i < argc; i++)
        {

            char fileName[100];
            char *givenFileName = getFileName(argv[i]);
            char numBlocksStr[12];
            int alreadyExists = 0;
            while (fread(fileName, 100, 1, archive) > 0)
            {
                fseek(archive, 12, SEEK_CUR);        //Skip fileSize
                fread(numBlocksStr, 12, 1, archive); //Read number of blocks
                int offset = (atoi(numBlocksStr) * 16);
                fseek(archive, offset, SEEK_CUR);
                if (strcmp(givenFileName, fileName) == 0)
                {
                    alreadyExists = 1;
                }
            }
            memset(numBlocksStr, 0, 12);

            if (alreadyExists)
            {
                printf("%s already exists. Skipping this file\n", givenFileName);
                continue;
            }
            rewind(archive);
            memset(fileName, '\0', 100);
            if (strlen(givenFileName) > 100)
            {
                printf("File name is too big for archiving. %s will be skipped.\n", givenFileName);
                continue;
            }
            memcpy(fileName, givenFileName, strlen(givenFileName));
            FILE *tmp = tmpfile();
            FILE *fileToEncrypt = fopen(argv[i], "rb");
            int fileSize = encrypt_cbc(fileToEncrypt, tmp, hPass);
            if (fileSize > 999999999999)
            {
                printf("File is too big for archiving. %s will be skipped\n", givenFileName);
                continue;
            }
            if (fileSize < 0)
            {
                continue;
            }
            fseek(tmp, 0, SEEK_END);
            long int numBlocks = ftell(tmp) / 16;
            printf("Archiving %s into %s\n", fileName, archiveName);
            appendFile(tmp, fileName, fileSize, numBlocks, archive);
            fclose(tmp);
        }
        fseek(archive, 0, SEEK_END);
        int archiveSize = ftell(archive);
        if (archiveSize == 0)
        {
            printf("Archive is empty. It will be deleted.\n");
            remove(archiveName);
        }
        else
        {
            appendHMAC(archive, hPass);
        }
        fclose(archive);
    }
    else if (strcmp(argv[1], "extract") == 0)
    {
        if (!archiveExists)
        {
            printf("Can not find the archive, %s\n", archiveName);
            return 0;
        }
        FILE *archive = fopen(archiveName, "ab+");
        if (archive)
        {
            removeHMAC(archive);
            rewind(archive);
            char fileName[100];
            char fileSizeStr[12];
            char numBlocksStr[12];
            for (int i = firstFile; i < argc; i++)
            {
                int found = 0;
                while (fread(fileName, 100, 1, archive) > 0)
                {
                    fread(fileSizeStr, 12, 1, archive);
                    fread(numBlocksStr, 12, 1, archive);
                    int fileSize = atoi(fileSizeStr);
                    int numBlocks = atoi(numBlocksStr);
                    if (strcmp(fileName, argv[i]) == 0)
                    {
                        found = 1;
                        FILE *newFile = fopen(fileName, "wb+"); // WILL OVERWRITE EXISTING
                        decrypt_cbc(archive, hPass, newFile, fileSize, numBlocks);
                        fclose(newFile);
                        break;
                    }
                    else
                    {
                        int offset = (atoi(numBlocksStr) * 16);
                        fseek(archive, offset, SEEK_CUR);
                    }
                }
                if (!found)
                {
                    printf("%s was not found. It will be skipped.\n", argv[i]);
                }
                rewind(archive);
            }
            appendHMAC(archive, hPass);
            fclose(archive);
        }
        else
        {
            printf("The archive `%s` was not found\n", archiveName);
        }
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
        FILE *archive = fopen(archiveName, "ab+");
        if (archive)
        {
            removeHMAC(archive);
            rewind(archive);
            char fileName[100];
            char fileSizeStr[12];
            char numBlocksStr[12];
            for (int i = firstFile; i < argc; i++)
            {
                int found = 0;
                FILE *tp = tmpfile();
                while (fread(fileName, 100, 1, archive) > 0)
                {

                    fread(fileSizeStr, 12, 1, archive);
                    fread(numBlocksStr, 12, 1, archive);
                    int numBlocks = atoi(numBlocksStr);
                    int offset = (numBlocks * 16);
                    if (strcmp(fileName, argv[i]) == 0)
                    {
                        found = 1;
                        fseek(archive, offset, SEEK_CUR);
                    }
                    else
                    {
                        fwrite(fileName, 100, 1, tp);
                        fwrite(fileSizeStr, 12, 1, tp);
                        fwrite(numBlocksStr, 12, 1, tp);
                        BYTE *cipher = (BYTE *)malloc(offset + 1);
                        fread(cipher, offset, 1, archive);
                        fwrite(cipher, offset, 1, tp);
                        free(cipher);
                    }
                }
                if (found)
                {
                    rewind(tp);
                    fclose(fopen(archiveName, "wb"));
                    BYTE buff[1];
                    int read = 0;
                    rewind(tp);
                    while ((read = fread(buff, 1, 1, tp) > 0))
                    {
                        fwrite(buff, 1, read, archive);
                    }
                }
                else
                {
                    printf("%s was not found. It will be skipped.\n", argv[i]);
                }
                rewind(archive);
                fclose(tp);
            }
            fseek(archive, 0, SEEK_END);
            int archiveSize = ftell(archive);
            if (archiveSize == 0)
            {
                printf("Archive is empty. It will be deleted.\n");
                remove(archiveName);
            }
            else
            {
                appendHMAC(archive, hPass);
            }
            fclose(archive);
        }
        else
        {
            printf("The archive `%s` was not found\n", archiveName);
        }
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