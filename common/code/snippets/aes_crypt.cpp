#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*3) // an output buffer must be a multiple of the key size

//params: <input file> <output file> <is decrypt mode> <key>
int wmain( int argc, wchar_t *argv[])
{
    if (argc < 4) {
        printf ("params: <input file> <output file> <is decrypt mode> [*key]\n");
        system("pause");
        return 0;
    }
    wchar_t *filename = argv[1];
    wchar_t *filename2 = argv[2];

    wchar_t default_key[] = L"3igcZhRdWq96m3GUmTAiv9";
    wchar_t *key_str = default_key;

    BOOL isDecrypt = FALSE;
    if (argv[3][0] > '0') {
        printf("Decrypt mode\n");
        isDecrypt = TRUE;
    }
    if (argc >= 5) {
        key_str = argv[4];
    }
    size_t len = lstrlenW(key_str);

    printf("Key: %S\n", key_str);
    printf("Key len: %#x\n", len);
    printf("Input File: %S\n", filename);
    printf("Output File: %S\n", filename2);
    printf("----\n");

    HANDLE hInpFile = CreateFileW(filename, GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hInpFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open input file!\n");
        system("pause");
        return (-1);
    }
    HANDLE hOutFile = CreateFileW(filename2, GENERIC_WRITE, 0,  NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);          
    if (hOutFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open output file!\n");
        system("pause");
        return (-1);
    }

    if (isDecrypt) {
        printf("DECRYPTING\n");
    } else {
        printf("ENCRYPTING\n");
    }

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }

    if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
        DWORD err = GetLastError();
        printf ("CryptHashData Failed : %#x\n", err);
        system("pause");
        return (-1);
    }
    printf ("[+] CryptHashData Success\n");

    HCRYPTKEY hKey;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0,&hKey)){
        dwStatus = GetLastError();
        printf("CryptDeriveKey failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }
    printf ("[+] CryptDeriveKey Success\n");
    
    const size_t chunk_size = CHUNK_SIZE;
    BYTE chunk[chunk_size] = { 0 };
    DWORD out_len = 0;

    BOOL isFinal = FALSE;
    DWORD readTotalSize = 0;
    
    DWORD inputSize = GetFileSize(hInpFile, NULL);

    while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) {
        if (0 == out_len){
            break;
        }
        readTotalSize += out_len;
        if (readTotalSize == inputSize) {
            isFinal = TRUE;
            printf("Final chunk set.\n");
        }

        if (isDecrypt) {
            if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
                printf("[-] CryptDecrypt failed\n");
                break;
            }
        } else {
            if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
                printf("[-] CryptEncrypt failed\n");
                break;
            }
        }
        DWORD written = 0;
        if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
            printf("writing failed!\n");
            break;
        }
        memset(chunk, 0, chunk_size);
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);

    CloseHandle(hInpFile);
    CloseHandle(hOutFile);
    printf("Finished. Processed %#x bytes.\n", readTotalSize);
    system("pause");
    return 0;
}
