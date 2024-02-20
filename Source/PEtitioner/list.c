#include <list.h>

VOID
KDUAPI
KduInitListHead(
	_In_ PLIST_ENTRY List
)
{
	List->Flink = List;
	List->Blink = List;
}

VOID
KDUAPI
KduInsertListTail(
	_In_ PLIST_ENTRY List,
	_In_ PLIST_ENTRY Entry
)
{
	Entry->Flink = List;
	Entry->Blink = List->Blink;

	List->Blink->Flink = Entry;
	List->Blink = Entry;
}

BOOL
KDUAPI
KduIsListEmpty(
	_In_ PLIST_ENTRY List
)
{
	return (List->Flink == List) && (List->Blink == List);
}

PLIST_ENTRY
KDUAPI
KduRemoveHeadList(
	_In_ PLIST_ENTRY List
)
{
	PLIST_ENTRY entry = NULL;

	if (KduIsListEmpty(List))
	{
		return NULL;
	}

	entry = List->Flink;

	List->Flink = entry->Flink;
	entry->Flink->Blink = List;

	entry->Flink = entry->Blink = NULL;

	return entry;
}

DWORD
KDUAPI
KduCountListEntries(
	_In_ PLIST_ENTRY List
)
{
	DWORD count = 0;

	PLIST_ENTRY entry = List->Flink;
	while (entry != List)
	{
		count++;

		entry = entry->Flink;
	}

	return count;
}