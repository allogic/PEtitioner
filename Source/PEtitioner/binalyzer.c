#include <binalyzer.h>
#include <log.h>

DWORD
KDUAPI
KduGetFunctionSize(
	_In_ PVOID Base
)
{
	PBYTE ptr = (PBYTE)Base;
	while (*ptr != 0xCC) ptr++;
	return (DWORD)((DWORD64)ptr - (DWORD64)Base);
}

DWORD
KDUAPI
KduGetSectionScratchSpaceOffset(
	_In_ PVOID Image,
	_In_ DWORD SectionOffset,
	_In_ DWORD SectionSize
)
{
	PBYTE ptr = (PBYTE)Image + SectionOffset + SectionSize - 1;
	while (*ptr == 0x0) ptr--;
	return (DWORD)((DWORD64)ptr - ((DWORD64)Image + SectionOffset));
}

DWORD
KDUAPI
KduGetSectionScratchSpaceSize(
	_In_ PVOID Image,
	_In_ DWORD SectionOffset,
	_In_ DWORD SectionSize
)
{
	PBYTE ptr = (PBYTE)Image + SectionOffset + SectionSize - 1;
	while (*ptr == 0x00) ptr--;
	return (DWORD)(((DWORD64)Image + SectionOffset + SectionSize - 1) - (DWORD64)ptr);
}

DWORD
KDUAPI
KduFindPhysicalOffsetByPattern(
	_In_ PVOID Image,
	_In_ DWORD ImageSize,
	_In_ LPCSTR Pattern
)
{
	DWORD offset = 0;

	DWORD patternSize = (DWORD)strlen(Pattern);

	for (DWORD i = 0; i < ImageSize; i++)
	{
		BOOL found = TRUE;

		for (DWORD j = 0; j < patternSize; j++)
		{
			if (*((PBYTE)Image + i + j) != *((PBYTE)Pattern + j))
			{
				found = FALSE;

				break;
			}
		}

		if (found)
		{
			offset = i;

			break;
		}
	}

	return offset;
}