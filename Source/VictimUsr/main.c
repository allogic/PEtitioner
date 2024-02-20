#include <stdio.h>

#include <windows.h>

INT main()
{
	DWORD gold = 0;

	while (TRUE)
	{
		printf("Gold %u\n", gold);

		Sleep(1000);

		gold++;
	}

	return 0;
}