#include <wdm.h>

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "Unloaded");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT Driver,
    _In_ PUNICODE_STRING RegistrationPath
)
{
    UNREFERENCED_PARAMETER(RegistrationPath);

    NTSTATUS status = STATUS_SUCCESS;

    Driver->DriverUnload = DriverUnload;

    DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "Loaded");

    return status;
}