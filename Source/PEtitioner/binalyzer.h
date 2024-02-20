#ifndef KDU_BINALYZER_H
#define KDU_BINALYZER_H

#include <windows.h>

#include <core.h>

DWORD
KDUAPI
KduGetFunctionSize(
	_In_ PVOID Base);

DWORD
KDUAPI
KduGetSectionScratchSpaceOffset(
	_In_ PVOID Image,
	_In_ DWORD SectionOffset,
	_In_ DWORD SectionSize);

DWORD
KDUAPI
KduGetSectionScratchSpaceSize(
	_In_ PVOID Image,
	_In_ DWORD SectionOffset,
	_In_ DWORD SectionSize);

DWORD
KDUAPI
KduFindPhysicalOffsetByPattern(
	_In_ PVOID Image,
	_In_ DWORD ImageSize,
	_In_ LPCSTR Pattern);

#endif