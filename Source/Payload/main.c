#include <stdio.h>

#include <windows.h>

#define PAYLOADAPI __declspec(dllexport)

PAYLOADAPI VOID KduAsmPayload(VOID);

PAYLOADAPI VOID KduFakeMain(
	_In_ INT argc,
	_In_ PCHAR* argv,
	_In_ PCHAR* envp);

PAYLOADAPI VOID KduFakeMain(
	_In_ INT argc,
	_In_ PCHAR* argv,
	_In_ PCHAR* envp
)
{
	printf("Hello Fake Main");
}

INT main()
{
	return 0;
}