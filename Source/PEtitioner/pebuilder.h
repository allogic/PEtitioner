#ifndef KDU_PEBUILDER_H
#define KDU_PEBUILDER_H

#include <windows.h>

#include <core.h>

VOID
KDUAPI
KduInitPeBuilder(
	_In_ LPCSTR ImagePath);

VOID
KDUAPI
KduAddNewSection(
	_In_ LPCSTR SectionName,
	_In_ DWORD SectionSize,
	_In_ DWORD Characteristics);

VOID
KDUAPI
KduResizeSection(
	_In_ LPCSTR SectionName,
	_In_ DWORD SectionSize);

VOID
KDUAPI
KduCopyFunctionByPatternIntoSection(
	_In_ LPCSTR FunctionPattern,
	_In_ LPCSTR SectionName,
	_In_ DWORD FunctionOffset);

VOID
KDUAPI
KduPatchFunctionByPatternWithInt3(
	_In_ LPCSTR FunctionPattern);

VOID
KDUAPI
KduUpdateSections(
	_In_ PLIST_ENTRY Sections);

VOID
KDUAPI
KduBuildPeImage(
	_In_ PLIST_ENTRY Sections);

VOID
KDUAPI
KduReleasePeBuilder(
	_In_ LPCSTR ImagePath);

#endif