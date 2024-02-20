#ifndef KDU_SRVMGR_H
#define KDU_SRVMGR_H

#include <windows.h>

#include <core.h>

BOOL
KDUAPI
KduListAllServices();

BOOL
KDUAPI
KduPrintServiceStatus(
    _In_ LPCSTR ServiceName);

BOOL
KDUAPI
KduStartService(
    _In_ LPCSTR ServiceName);

BOOL
KDUAPI
KduStopService(
    _In_ LPCSTR ServiceName);

BOOL
KDUAPI
KduPrintServiceCertificate(
    _In_ LPCSTR ServiceName);

#endif