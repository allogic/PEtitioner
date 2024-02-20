#include <log.h>

VOID
KDUAPI
KduDumpHex(
	_In_ PVOID Address,
	_In_ DWORD64 Size,
	_In_ DWORD Stride
)
{
	for (DWORD64 i = 0; i < Size; i += Stride)
	{
		for (DWORD j = 0; j < Stride; j++)
		{
			if (i + j < Size)
			{
				printf("%02X ", ((PBYTE)Address)[i + j]);
			}
			else
			{
				printf("   ");
			}
		}

		for (DWORD64 j = 0; j < Stride; j++)
		{
			if (i + j < Size)
			{
				if (((PBYTE)Address)[i + j] >= 32 && ((PBYTE)Address)[i + j] < 127)
				{
					printf("%c", ((PBYTE)Address)[i + j]);
				}
				else
				{
					printf(".");
				}
			}
		}

		if (Size > Stride)
		{
			printf("\n");
		}
	}
}