#ifndef KDU_LOG_H
#define KDU_LOG_H

#include <stdio.h>

#include <windows.h>

#include <core.h>

#define KDU_INFO(FORMAT, ...) printf(FORMAT, __VA_ARGS__)

#define KDU_ERROR(FORMAT, ...) \
{ \
    printf(FORMAT, __VA_ARGS__); \
    DWORD lastError = GetLastError(); \
    if (lastError > ERROR_SUCCESS) \
    { \
        LPVOID buffer = NULL; \
        DWORD size = FormatMessage( \
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
            NULL, lastError, \
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), \
            (LPSTR)&buffer, 0, NULL); \
        printf("File:%s\n", __FILE__); \
        printf("Line:%u\n", __LINE__); \
        printf("Error:0x%08X\n", lastError); \
        printf("Message:%s\n", (LPSTR)buffer); \
        LocalFree(buffer); \
        SetLastError(ERROR_SUCCESS); \
    } \
}

VOID
KDUAPI
KduDumpHex(
    _In_ PVOID Address,
    _In_ DWORD64 Size,
    _In_ DWORD Stride);

#endif