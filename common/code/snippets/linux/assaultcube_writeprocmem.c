/ Process ID Finder
// Matthew Geiger

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>
#include <string.h>
#include <dirent.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>

#define bool u_int8_t

#define _PROC_FOLDER "/proc/"
#define _PROC_STATUS "status"
#define _PROC_STATUS_BUFFER_SIZE 4096
#define _PROC_STATUS_NAME_OFFSET 0x6
#define _PROC_STATUS_ID_SIZE 0x4

#define _NEW_LINE_CHARACTER '\n'

#define TRUE 1
#define FALSE 0

const char szTargetProcessName[] = "ac_client";
const char szSignature[] = "\x48\x8b\x45\x28\x83\x28\x01\x48";
const char szOpCode[] = "\x90\x90\x90";

// Scans proc file system for supplied process name
__UINTPTR_TYPE__ GetProcessId(const char *szProcessName) {
    // Directory Properties
    DIR *Directory;
    struct dirent *DirectoryProperties;

    // Process information buffer
    char *szStatusBuffer = (char *)malloc(_PROC_STATUS_BUFFER_SIZE);
    char *szProcessNameBuffer = (char *)malloc(sizeof(char) * 64);
    char *szProcessIdBuffer = (char *)malloc(sizeof(char) * 64);

    // Change working directory
    chdir(_PROC_FOLDER);

    // Open and scan proc directory properties
    Directory = opendir(_PROC_FOLDER);
    while((DirectoryProperties = readdir(Directory)) != NULL) {
        // Change CWD to scanned directory
        chdir(DirectoryProperties->d_name);

        // Define file path
        char szStatusFileDirectory[64];
        sprintf(szStatusFileDirectory, "/proc/%ld/status", (unsigned long)(atol(DirectoryProperties->d_name)));

        // Open the status proc member
        int StatusFd = open(szStatusFileDirectory, O_RDONLY);
        if(!StatusFd)
            return 0;

        // Read contents of status to buffer on heap
        if(!read(StatusFd, szStatusBuffer, _PROC_STATUS_BUFFER_SIZE))
            return 0;

        // Process name file offset
        int StatusIndex = _PROC_STATUS_NAME_OFFSET;

        // Define found process name flag
        bool bFoundNameFlag = FALSE;

        // Scan process name
        while(TRUE) {
            // Check for null byte or newline character
            if(szStatusBuffer[StatusIndex] == 0 || szStatusBuffer[StatusIndex] == _NEW_LINE_CHARACTER) {
                szProcessNameBuffer[StatusIndex - _PROC_STATUS_NAME_OFFSET] = 0;
                bFoundNameFlag = TRUE;
                break;
            }

            // Read memory to szProcessNameBuffer
            szProcessNameBuffer[StatusIndex - _PROC_STATUS_NAME_OFFSET] = szStatusBuffer[StatusIndex];
            StatusIndex++;
        }

        // Create section check buffer
        char szProcIdCheckBuffer[64];

        // Scan process id
        if(bFoundNameFlag && !strcmp(szProcessName, szProcessNameBuffer)) {
            // Proc id section
            int iMainIndex = 0;

            // Scan for "Pid:"
            while(TRUE) {
                for(unsigned int i = 0; i < _PROC_STATUS_ID_SIZE + 1; i++) {
                    szProcIdCheckBuffer[i] = szStatusBuffer[iMainIndex];
                    iMainIndex++;
                }

                szProcIdCheckBuffer[_PROC_STATUS_ID_SIZE] = 0;

                if(!strcmp(szProcIdCheckBuffer, "Pid:"))
                    break;

                iMainIndex -= 4;
            }

            // Scan process id
            int iMainPidIndex = iMainIndex;
            int iPidIndex = 0;
            while(TRUE) {
                if(szStatusBuffer[iMainPidIndex] == 0 || szStatusBuffer[iMainPidIndex] == _NEW_LINE_CHARACTER) {
                    szProcessIdBuffer[iPidIndex] = 0;
                    bFoundNameFlag = TRUE;
                    break;
                }

                szProcessIdBuffer[iPidIndex] = szStatusBuffer[iMainPidIndex];
                iPidIndex++;
                iMainPidIndex++;
            }
            break;
        }

        // Close status file descriptor
        close(StatusFd);
    }

    // Close directory descriptor
    closedir(Directory);

    // Define process id
    __UINTPTR_TYPE__ uProcessID = (__UINTPTR_TYPE__)(atol(szProcessIdBuffer));

    // Free memory
    free(szStatusBuffer);
    free(szProcessNameBuffer);
    free(szProcessIdBuffer);

    // Return process id
    return uProcessID;
}

__UINTPTR_TYPE__ GetProcessBaseAddress(__UINTPTR_TYPE__ uProcessId) {
    // Create temp buffers
    char *szMemoryBuffer = (char *)malloc(sizeof(char) * 32);
    char *szMemoryAddressBuffer = (char *)malloc(sizeof(char) * 32);

    // Create file path
    char szFilePath[64];
    sprintf(szFilePath, "/proc/%ld/maps", uProcessId);

    // Open target virtual memory
    int fd = open(szFilePath, O_RDONLY);
    if(!fd)
        return 0;

    // Read memory into buffer
    read(fd, szMemoryBuffer, sizeof(char) * 32);

    int StatusIndex = 0;

    // Scan map
    while(TRUE) {
        // Check for null byte or newline character
        if(szMemoryBuffer[StatusIndex] == '-' || szMemoryBuffer[StatusIndex] == _NEW_LINE_CHARACTER ||
        szMemoryBuffer[StatusIndex] == 0) {
            szMemoryAddressBuffer[StatusIndex] = 0;
            break;
        }

        // Read memory to szProcessNameBuffer
        szMemoryAddressBuffer[StatusIndex] = szMemoryBuffer[StatusIndex];
        StatusIndex++;
    }

    // Close fd
    close(fd);

    // Convert ascii to hex address
    __UINTPTR_TYPE__ uBaseAddress = (__UINTPTR_TYPE__)(strtol(szMemoryAddressBuffer, NULL, 16));

    // Free memory
    free(szMemoryBuffer);
    free(szMemoryAddressBuffer);

    return uBaseAddress;
}

bool ReadProcessMemory(int fd, __UINTPTR_TYPE__ uAddress, void *buffer, unsigned int size) {
    if(!pread(fd, buffer, size, uAddress))
        return FALSE;

    return TRUE;
}

bool WriteProcessMemory(int fd, __UINTPTR_TYPE__ uAddress, void *buffer, unsigned int size) {
    if(!pwrite(fd, buffer, size, uAddress))
        return FALSE;

    return TRUE;
}

__UINTPTR_TYPE__ FindAddressSignature(int fd, const char *szSignature, __UINTPTR_TYPE__ uBaseAddress, unsigned long iScanSize) {
    unsigned int iSignatureSize = (long unsigned int)strlen(szSignature);

    // Found memory flag
    bool bFoundFlag = FALSE;

    // Temp memory buffer
    char *szMemory = (char *)malloc(sizeof(char) * iScanSize);
    ReadProcessMemory(fd, uBaseAddress, szMemory, iScanSize);

    for(unsigned long uIndex = 0; uIndex < iScanSize; uIndex++) {
        for(unsigned int j = 0; j < iSignatureSize; j++) {
            bFoundFlag = (szSignature[j] == szMemory[uIndex + j] || szSignature[j] == '?') ? TRUE : FALSE;
            if(!bFoundFlag)
                break;
        }

        if(bFoundFlag)
            return (__UINTPTR_TYPE__)(uBaseAddress + uIndex);
    }

    // Free memory
    free(szMemory);
    return 0;
}

int main(const int argc, const char *argv[]) {
    __UINTPTR_TYPE__ uProcessId = GetProcessId(szTargetProcessName);
    if(!uProcessId)
        return EXIT_FAILURE;

    printf("Pid: %ld\n", uProcessId);

    __UINTPTR_TYPE__ uBaseAddress = GetProcessBaseAddress(uProcessId);
    if(!uBaseAddress)
        return EXIT_FAILURE;

    printf("Base Address: 0x%lx\n", uBaseAddress);

    // Start ptrace
    ptrace(PTRACE_ATTACH, uProcessId, NULL, NULL);

    char szVirtualMem[64];
    sprintf(szVirtualMem, "/proc/%ld/mem", uProcessId);

    int fd = open(szVirtualMem, O_RDWR);
    if(!fd)
        return EXIT_FAILURE;

    char szMemoryBuffer[64];

    if(!ReadProcessMemory(fd, uBaseAddress, (void *)szMemoryBuffer, 4))
        return EXIT_FAILURE;

    for(int i = 0; i < 4; i++)
        printf("0x%02x | %c\n", szMemoryBuffer[i], szMemoryBuffer[i]);

    __UINTPTR_TYPE__ uSignatureAddress = FindAddressSignature(fd, szSignature, uBaseAddress, 75939840);
    if(!uSignatureAddress)
        return EXIT_FAILURE;

    uSignatureAddress += 4;

    printf("Address: 0x%lx\n", uSignatureAddress);

    WriteProcessMemory(fd, uSignatureAddress, szOpCode, 3);

    close(fd);

    // End ptrace
    ptrace(PTRACE_DETACH, uProcessId, NULL, NULL);

    return EXIT_SUCCESS;
}
