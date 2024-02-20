#include <fileio.h>
#include <log.h>

BOOL
KDUAPI
KduReadBinaryFile(
    _In_ LPCSTR FilePath,
    _Inout_ PVOID* Buffer,
    _Inout_ PDWORD BufferSize
)
{
    HANDLE file = CreateFile(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE)
    {
        KDU_ERROR("Invalid file handle\n");

        return FALSE;
    }

    DWORD bufferSize = GetFileSize(file, NULL);
    PBYTE buffer = (PBYTE)malloc(bufferSize);

    if (ReadFile(file, buffer, bufferSize, NULL, NULL) == FALSE)
    {
        KDU_ERROR("Could not read file\n");

        free(buffer);

        CloseHandle(file);

        return FALSE;
    }

    CloseHandle(file);

    *Buffer = buffer;
    *BufferSize = bufferSize;

    return TRUE;
}

BOOL
KDUAPI
KduWriteBinaryFile(
    _In_ LPCSTR FilePath,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
)
{
    HANDLE file = CreateFile(FilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE)
    {
        KDU_ERROR("Invalid file handle\n");

        return FALSE;
    }

    if (WriteFile(file, Buffer, BufferSize, NULL, NULL) == FALSE)
    {
        KDU_ERROR("Could not write file\n");

        CloseHandle(file);

        return FALSE;
    }

    CloseHandle(file);

    return TRUE;
}