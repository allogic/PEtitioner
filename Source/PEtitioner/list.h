#ifndef KDU_LIST_H
#define KDU_LIST_H

#include <windows.h>

#include <core.h>

VOID
KDUAPI
KduInitListHead(
	_In_ PLIST_ENTRY List);

VOID
KDUAPI
KduInsertListTail(
	_In_ PLIST_ENTRY List,
	_In_ PLIST_ENTRY Entry);

BOOL
KDUAPI
KduIsListEmpty(
	_In_ PLIST_ENTRY List);

PLIST_ENTRY
KDUAPI
KduRemoveHeadList(
	_In_ PLIST_ENTRY List);

DWORD
KDUAPI
KduCountListEntries(
	_In_ PLIST_ENTRY List);

#endif