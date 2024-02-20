#include <x64resolver.h>
#include <log.h>

#define KDU_X64_VERBOSE 1

#ifdef KDU_X64_VERBOSE
	#define KDU_X64_LOG(FORMAT, ...) KDU_INFO(FORMAT, __VA_ARGS__)
#else
	#define KDU_X64_LOG(FORMAT, ...)
#endif

VOID
KDUAPI
KduResolveFunction(
	_In_ PVOID Image,
	_In_ DWORD PhysicalFunctionOffset,
	_In_ DWORD PhysicalFunctionSize,
	_In_ DWORD OldVirtualSectionOffset,
	_In_ DWORD NewVirtualSectionOffset
)
{
	PBYTE src = (PBYTE)Image + PhysicalFunctionOffset;
	PBYTE dst = (PBYTE)Image + PhysicalFunctionOffset + PhysicalFunctionSize;

	while (src != dst)
	{
		BYTE opCode = *src;

		switch (opCode)
		{
			///////////////////////////////////////////////
			// INC
			///////////////////////////////////////////////

			case 0x40: // EAX
			{
				src += 1;
				KDU_X64_LOG("INC EAX\n");
				break;
			}
			case 0x41: // ECX
			{
				src += 1;
				KDU_X64_LOG("INC ECX\n");
				break;
			}
			case 0x42: // EDX
			{
				src += 1;
				KDU_X64_LOG("INC EDX\n");
				break;
			}
			case 0x43: // EBX
			{
				src += 1;
				KDU_X64_LOG("INC EBX\n");
				break;
			}
			case 0x44: // ESP
			{
				src += 1;
				KDU_X64_LOG("INC ESP\n");
				break;
			}
			case 0x45: // EBP
			{
				src += 1;
				KDU_X64_LOG("INC EBP\n");
				break;
			}
			case 0x46: // ESI
			{
				src += 1;
				KDU_X64_LOG("INC ESI\n");
				break;
			}
			case 0x47: // EDI
			{
				src += 1;
				KDU_X64_LOG("INC EDI\n");
				break;
			}

			///////////////////////////////////////////////
			// PUSH
			///////////////////////////////////////////////

			case 0x50: // EAX
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH EAX\n");
				break;
			}
			case 0x51: // ECX
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH ECX\n");
				break;
			}
			case 0x52: // EDX
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH EDX\n");
				break;
			}
			case 0x53: // EBX
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH EBX\n");
				break;
			}
			case 0x54: // ESP
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH ESP\n");
				break;
			}
			case 0x55: // EBP
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH EBP\n");
				break;
			}
			case 0x56: // ESI
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH ESI\n");
				break;
			}
			case 0x57: // EDI
			{
				BYTE extendedMode = *(src + 1);
				src += 2;
				KDU_X64_LOG("PUSH EDI\n");
				break;
			}

			case 0x6A: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0x68: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0xE0: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0x16: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0x1E: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0x06: KDU_ASSERT(0, "OpCode not implemented"); break;
			case 0x0F: KDU_ASSERT(0, "OpCode not implemented"); break;

			///////////////////////////////////////////////
			// SUB
			///////////////////////////////////////////////

			case 0x83:
			{
				BYTE mod = *(src + 1);
				switch (mod)
				{
					case 0xEC: // ESP
					{
						BYTE value = *(src + 2);
						KDU_X64_LOG("SUB ESP 0x%02X\n", value);
						break;
					}

					default: KDU_ASSERT(0, "Mod not implemented"); break;
				}
				src += 3;
				break;
			}

			///////////////////////////////////////////////
			// XOR
			///////////////////////////////////////////////

			case 0x33:
			{
				break;
			}

			///////////////////////////////////////////////
			// CALL
			///////////////////////////////////////////////

			case 0xE8:
			{
				BYTE relativeVirtualOffset = *(src + 1);
				src += 5;
				KDU_X64_LOG("CALL REL 0x%02X\n", relativeVirtualOffset);
				break;
			}
			case 0x9A: KDU_ASSERT(0, "OpCode not implemented"); break;

			///////////////////////////////////////////////
			// NONE
			///////////////////////////////////////////////

			default: KDU_ASSERT(0, "OpCode not implemented"); break;
		}
	}
}