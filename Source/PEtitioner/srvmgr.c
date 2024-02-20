#include <srvmgr.h>
#include <log.h>

#include <psapi.h>

BOOL
KDUAPI
KduListAllServices()
{
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (serviceManager == NULL)
    {
        KDU_ERROR("Failed opening service manager\n");

        return FALSE;
    }

    DWORD bytesNeeded = 0;
    DWORD bufferSize = 0;
    DWORD servicesReturned = 0;

    EnumServicesStatus(serviceManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, NULL);

    if (GetLastError() != ERROR_MORE_DATA)
    {
        KDU_ERROR("Failed receiving service status count\n");

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    bufferSize = bytesNeeded;

    LPENUM_SERVICE_STATUS services = (LPENUM_SERVICE_STATUS)malloc(bufferSize);

    if (EnumServicesStatus(serviceManager, SERVICE_WIN32, SERVICE_STATE_ALL, services, bufferSize, &bytesNeeded, &servicesReturned, NULL) == FALSE)
    {
        KDU_ERROR("Failed receiving service status\n");

        free(services);

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    for (DWORD i = 0; i < servicesReturned; i++)
    {
        KDU_INFO("ServiceName:%s ", services[i].lpServiceName);
        KDU_INFO("DisplayName:%s ", services[i].lpDisplayName);

        KDU_INFO("Type:");
        switch (services[i].ServiceStatus.dwServiceType)
        {
            case SERVICE_KERNEL_DRIVER: KDU_INFO("SERVICE_KERNEL_DRIVER"); break;
            case SERVICE_FILE_SYSTEM_DRIVER: KDU_INFO("SERVICE_FILE_SYSTEM_DRIVER"); break;
            case SERVICE_ADAPTER: KDU_INFO("SERVICE_ADAPTER"); break;
            case SERVICE_RECOGNIZER_DRIVER: KDU_INFO("SERVICE_RECOGNIZER_DRIVER"); break;
            case SERVICE_DRIVER: KDU_INFO("SERVICE_DRIVER"); break;
            case SERVICE_WIN32_OWN_PROCESS: KDU_INFO("SERVICE_WIN32_OWN_PROCESS"); break;
            case SERVICE_WIN32_SHARE_PROCESS: KDU_INFO("SERVICE_WIN32_SHARE_PROCESS"); break;
            case SERVICE_WIN32: KDU_INFO("SERVICE_WIN32"); break;
            case SERVICE_USER_SERVICE: KDU_INFO("SERVICE_USER_SERVICE"); break;
            case SERVICE_USERSERVICE_INSTANCE: KDU_INFO("SERVICE_USERSERVICE_INSTANCE"); break;
            case SERVICE_USER_SHARE_PROCESS: KDU_INFO("SERVICE_USER_SHARE_PROCESS"); break;
            case SERVICE_USER_OWN_PROCESS: KDU_INFO("SERVICE_USER_OWN_PROCESS"); break;
            case SERVICE_INTERACTIVE_PROCESS: KDU_INFO("SERVICE_INTERACTIVE_PROCESS"); break;
            case SERVICE_PKG_SERVICE: KDU_INFO("SERVICE_PKG_SERVICE"); break;
            case SERVICE_TYPE_ALL: KDU_INFO("SERVICE_TYPE_ALL"); break;
        }
        KDU_INFO(" ");

        KDU_INFO("State:");
        switch (services[i].ServiceStatus.dwCurrentState)
        {
            case SERVICE_STOPPED: KDU_INFO("SERVICE_STOPPED"); break;
            case SERVICE_START_PENDING: KDU_INFO("SERVICE_START_PENDING"); break;
            case SERVICE_STOP_PENDING: KDU_INFO("SERVICE_STOP_PENDING"); break;
            case SERVICE_RUNNING: KDU_INFO("SERVICE_RUNNING"); break;
            case SERVICE_CONTINUE_PENDING: KDU_INFO("SERVICE_CONTINUE_PENDING"); break;
            case SERVICE_PAUSE_PENDING: KDU_INFO("SERVICE_PAUSE_PENDING"); break;
            case SERVICE_PAUSED: KDU_INFO("SERVICE_PAUSED"); break;
        }
        KDU_INFO("\n");
    }

    free(services);

    CloseServiceHandle(serviceManager);

    return TRUE;
}

BOOL
KDUAPI
KduPrintServiceStatus(
    _In_ LPCSTR ServiceName
)
{
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (serviceManager == NULL)
    {
        KDU_ERROR("Failed opening service manager\n");

        return FALSE;
    }

    SC_HANDLE service = OpenService(serviceManager, ServiceName, SERVICE_QUERY_STATUS);

    if (service == NULL)
    {
        KDU_ERROR("Failed opening service\n");

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded) == FALSE)
    {
        KDU_ERROR("Failed quering service status\n");

        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    KDU_INFO("Type:");
    switch (serviceStatus.dwServiceType)
    {
        case SERVICE_KERNEL_DRIVER: KDU_INFO("SERVICE_KERNEL_DRIVER"); break;
        case SERVICE_FILE_SYSTEM_DRIVER: KDU_INFO("SERVICE_FILE_SYSTEM_DRIVER"); break;
        case SERVICE_ADAPTER: KDU_INFO("SERVICE_ADAPTER"); break;
        case SERVICE_RECOGNIZER_DRIVER: KDU_INFO("SERVICE_RECOGNIZER_DRIVER"); break;
        case SERVICE_DRIVER: KDU_INFO("SERVICE_DRIVER"); break;
        case SERVICE_WIN32_OWN_PROCESS: KDU_INFO("SERVICE_WIN32_OWN_PROCESS"); break;
        case SERVICE_WIN32_SHARE_PROCESS: KDU_INFO("SERVICE_WIN32_SHARE_PROCESS"); break;
        case SERVICE_WIN32: KDU_INFO("SERVICE_WIN32"); break;
        case SERVICE_USER_SERVICE: KDU_INFO("SERVICE_USER_SERVICE"); break;
        case SERVICE_USERSERVICE_INSTANCE: KDU_INFO("SERVICE_USERSERVICE_INSTANCE"); break;
        case SERVICE_USER_SHARE_PROCESS: KDU_INFO("SERVICE_USER_SHARE_PROCESS"); break;
        case SERVICE_USER_OWN_PROCESS: KDU_INFO("SERVICE_USER_OWN_PROCESS"); break;
        case SERVICE_INTERACTIVE_PROCESS: KDU_INFO("SERVICE_INTERACTIVE_PROCESS"); break;
        case SERVICE_PKG_SERVICE: KDU_INFO("SERVICE_PKG_SERVICE"); break;
        case SERVICE_TYPE_ALL: KDU_INFO("SERVICE_TYPE_ALL"); break;
    }
    KDU_INFO(" ");

    KDU_INFO("State:");
    switch (serviceStatus.dwCurrentState)
    {
        case SERVICE_STOPPED: KDU_INFO("SERVICE_STOPPED"); break;
        case SERVICE_START_PENDING: KDU_INFO("SERVICE_START_PENDING"); break;
        case SERVICE_STOP_PENDING: KDU_INFO("SERVICE_STOP_PENDING"); break;
        case SERVICE_RUNNING: KDU_INFO("SERVICE_RUNNING"); break;
        case SERVICE_CONTINUE_PENDING: KDU_INFO("SERVICE_CONTINUE_PENDING"); break;
        case SERVICE_PAUSE_PENDING: KDU_INFO("SERVICE_PAUSE_PENDING"); break;
        case SERVICE_PAUSED: KDU_INFO("SERVICE_PAUSED"); break;
    }
    KDU_INFO(" ");

    KDU_INFO("State:");
    switch (serviceStatus.dwControlsAccepted)
    {
        case SERVICE_ACCEPT_STOP: KDU_INFO("SERVICE_ACCEPT_STOP"); break;
        case SERVICE_ACCEPT_PAUSE_CONTINUE: KDU_INFO("SERVICE_ACCEPT_PAUSE_CONTINUE"); break;
        case SERVICE_ACCEPT_SHUTDOWN: KDU_INFO("SERVICE_ACCEPT_SHUTDOWN"); break;
        case SERVICE_ACCEPT_PARAMCHANGE: KDU_INFO("SERVICE_ACCEPT_PARAMCHANGE"); break;
        case SERVICE_ACCEPT_NETBINDCHANGE: KDU_INFO("SERVICE_ACCEPT_NETBINDCHANGE"); break;
        case SERVICE_ACCEPT_HARDWAREPROFILECHANGE: KDU_INFO("SERVICE_ACCEPT_HARDWAREPROFILECHANGE"); break;
        case SERVICE_ACCEPT_POWEREVENT: KDU_INFO("SERVICE_ACCEPT_POWEREVENT"); break;
        case SERVICE_ACCEPT_SESSIONCHANGE: KDU_INFO("SERVICE_ACCEPT_SESSIONCHANGE"); break;
        case SERVICE_ACCEPT_PRESHUTDOWN: KDU_INFO("SERVICE_ACCEPT_PRESHUTDOWN"); break;
        case SERVICE_ACCEPT_TIMECHANGE: KDU_INFO("SERVICE_ACCEPT_TIMECHANGE"); break;
        case SERVICE_ACCEPT_TRIGGEREVENT: KDU_INFO("SERVICE_ACCEPT_TRIGGEREVENT"); break;
        case SERVICE_ACCEPT_USER_LOGOFF: KDU_INFO("SERVICE_ACCEPT_USER_KDU_LOGOFF"); break;
        case SERVICE_ACCEPT_LOWRESOURCES: KDU_INFO("SERVICE_ACCEPT_LOWRESOURCES"); break;
        case SERVICE_ACCEPT_SYSTEMLOWRESOURCES: KDU_INFO("SERVICE_ACCEPT_SYSTEMLOWRESOURCES"); break;
    }
    KDU_INFO(" ");

    KDU_INFO("ExitCode:%u ", serviceStatus.dwWin32ExitCode);
    KDU_INFO("ServiceSpecificExitCode:%u ", serviceStatus.dwServiceSpecificExitCode);
    KDU_INFO("CheckPoint:%u ", serviceStatus.dwCheckPoint);
    KDU_INFO("WaitHint:%u ", serviceStatus.dwWaitHint);
    KDU_INFO("ProcessId:%u ", serviceStatus.dwProcessId);
    KDU_INFO("ProcessId:%X ", serviceStatus.dwServiceFlags);

    KDU_INFO("\n");

    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    return TRUE;
}

BOOL
KDUAPI
KduStartService(
    _In_ LPCSTR ServiceName
)
{
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (serviceManager == NULL)
    {
        KDU_ERROR("Failed opening service manager\n");

        return FALSE;
    }

    SC_HANDLE service = OpenService(serviceManager, ServiceName, SERVICE_ALL_ACCESS);

    if (service == NULL)
    {
        KDU_ERROR("Failed opening service\n");

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    if (StartService(service, 0, NULL) == FALSE)
    {
        KDU_ERROR("Failed starting service\n");

        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    KDU_INFO("Service %s started successfully\n", ServiceName);

    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    return TRUE;
}

BOOL
KDUAPI
KduStopService(
    _In_ LPCSTR ServiceName
)
{
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (serviceManager == NULL)
    {
        KDU_ERROR("Failed opening service manager\n");

        return FALSE;
    }

    SC_HANDLE service = OpenService(serviceManager, ServiceName, SERVICE_ALL_ACCESS);

    if (service == NULL)
    {
        KDU_ERROR("Failed opening service\n");

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    SERVICE_STATUS serviceStatus;

    if (ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus) == FALSE)
    {
        KDU_ERROR("Failed stopping service\n");

        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    KDU_INFO("Service %s stopped successfully\n", ServiceName);

    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    return TRUE;
}

BOOL
KDUAPI
KduPrintServiceCertificate(
    _In_ LPCSTR ServiceName
)
{
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (serviceManager == NULL)
    {
        KDU_ERROR("Failed opening service manager\n");

        return FALSE;
    }

    DWORD bytesNeeded = 0;

    SC_HANDLE service = OpenService(serviceManager, ServiceName, SERVICE_QUERY_STATUS);

    if (service == NULL)
    {
        KDU_ERROR("Failed opening service\n");

        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    SERVICE_STATUS_PROCESS serviceStatus;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded) == FALSE)
    {
        KDU_ERROR("Failed quering service status\n");

        CloseServiceHandle(service);
        CloseServiceHandle(serviceManager);

        return FALSE;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, serviceStatus.dwProcessId);

    if (process == NULL)
    {
        KDU_ERROR("Failed opening process\n");

        return FALSE;
    }

    HMODULE module;

    if (EnumProcessModules(process, &module, sizeof(module), &bytesNeeded) == FALSE)
    {
        KDU_ERROR("Failed enumerating process modules\n");

        CloseHandle(process);

        return FALSE;
    }

    CHAR moduleFileName[MAX_PATH];

    if (GetModuleFileNameEx(process, module, moduleFileName, sizeof(moduleFileName) / sizeof(CHAR)) == 0)
    {
        KDU_ERROR("Failed receiving module file name\n");

        CloseHandle(process);

        return FALSE;
    }

    HCERTSTORE certStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    if (certStore == NULL)
    {
        KDU_ERROR("Failed opening cert store\n");

        CloseHandle(process);

        return FALSE;
    }

    PCCERT_CONTEXT certContext = CertFindCertificateInStore(certStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);

    if (certContext == NULL)
    {
        KDU_ERROR("Failed finding cert in store\n");

        CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG);

        CloseHandle(process);

        return FALSE;
    }

    KDU_INFO("Subject:%s\n", (LPCSTR)certContext->pCertInfo->Subject.pbData);
    KDU_INFO("Issuer:%s\n", (LPCSTR)certContext->pCertInfo->Issuer.pbData);
    KDU_INFO("SerialNumber:%s\n", (LPCSTR)certContext->pCertInfo->SerialNumber.pbData);

    CertFreeCertificateContext(certContext);
    CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG);
    CloseHandle(process);

    return TRUE;
}
