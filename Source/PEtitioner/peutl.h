#ifndef KDU_PEUTL_H
#define KDU_PEUTL_H

#include <windows.h>

#include <core.h>

typedef BYTE IMAGE_DOS_STUB[192];

typedef struct _SECTION_ENTRY
{
	LIST_ENTRY ListEntry;
	IMAGE_SECTION_HEADER SectionHeader;
	PVOID SectionData;
} SECTION_ENTRY, *PSECTION_ENTRY;

WORD
KduRvaToSection(
	_In_ PIMAGE_SECTION_HEADER SectionHeaders,
	_In_ WORD NumberOfSections,
	_In_ DWORD Rva);

DWORD
KduRvaToOffset(
	_In_ PIMAGE_SECTION_HEADER SectionHeaders,
	_In_ WORD NumberOfSections,
	_In_ DWORD Rva);

BOOL
KDUAPI
KduIsImage32Bit(
	_In_ PVOID Image);

BOOL
KDUAPI
KduDumpPe32Header(
	_In_ PVOID Image);

BOOL
KDUAPI
KduDumpPe64Header(
	_In_ PVOID Image);

BOOL
KDUAPI
KduDumpPe32Sections(
	_In_ PVOID Image);

BOOL
KDUAPI
KduDumpPe64Sections(
	_In_ PVOID Image);

BOOL
KDUAPI
KduDumpPe32Section(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

BOOL
KDUAPI
KduDumpPe64Section(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

BOOL
KDUAPI
KduCollectPe32Sections(
	_In_ PVOID Image,
	_Out_ PLIST_ENTRY Sections);

BOOL
KDUAPI
KduCollectPe64Sections(
	_In_ PVOID Image,
	_Out_ PLIST_ENTRY Sections);

VOID
KDUAPI
KduFreeSections(
	_In_ PLIST_ENTRY Sections);

DWORD
KDUAPI
KduGetPe32PhysicalEntryOffset(
	_In_ PVOID Image);

DWORD
KDUAPI
KduGetPe64PhysicalEntryOffset(
	_In_ PVOID Image);

DWORD
KDUAPI
KduGetPe32PhysicalSectionOffset(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe64PhysicalSectionOffset(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe32PhysicalSectionSize(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe64PhysicalSectionSize(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe32VirtualSectionOffset(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe64VirtualSectionOffset(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe32VirtualSectionSize(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe64VirtualSectionSize(
	_In_ PVOID Image,
	_In_ LPCSTR SectionName);

DWORD
KDUAPI
KduGetPe32PhysicalExportOffset(
	_In_ PVOID Image,
	_In_ LPCSTR ExportName);

DWORD
KDUAPI
KduGetPe64PhysicalExportOffset(
	_In_ PVOID Image,
	_In_ LPCSTR ExportName);

#endif