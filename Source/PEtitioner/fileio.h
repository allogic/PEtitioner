#ifndef KDU_FILEIO_H
#define KDU_FILEIO_H

#include <windows.h>

#include <core.h>

BOOL
KDUAPI
KduReadBinaryFile(
	_In_ LPCSTR FilePath,
	_Inout_ PVOID* Buffer,
	_Inout_ PDWORD BufferSize);

BOOL
KDUAPI
KduWriteBinaryFile(
	_In_ LPCSTR FilePath,
	_In_ PVOID Buffer,
	_In_ DWORD BufferSize);

#endif