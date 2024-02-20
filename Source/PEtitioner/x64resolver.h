#ifndef KDU_X64RESOLVER_H
#define KDU_X64RESOLVER_H

#include <windows.h>

#include <core.h>

VOID
KDUAPI
KduResolveFunction(
	_In_ PVOID Image,
	_In_ DWORD PhysicalFunctionOffset,
	_In_ DWORD PhysicalFunctionSize,
	_In_ DWORD OldVirtualSectionOffset,
	_In_ DWORD NewVirtualSectionOffset);

#endif