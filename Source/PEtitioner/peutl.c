#include <string.h>

#include <peutl.h>
#include <list.h>
#include <log.h>

WORD
KduRvaToSection(
    _In_ PIMAGE_SECTION_HEADER SectionHeaders,
    _In_ WORD NumberOfSections,
    _In_ DWORD Rva
)
{
    for (WORD i = 0; i < NumberOfSections; i++)
    {
        if (Rva >= SectionHeaders[i].VirtualAddress)
        {
            if (Rva < (SectionHeaders[i].VirtualAddress + SectionHeaders[i].SizeOfRawData))
            {
                return i;
            }
        }
    }

    return 0;
}

DWORD
KduRvaToOffset(
    _In_ PIMAGE_SECTION_HEADER SectionHeaders,
    _In_ WORD NumberOfSections,
    _In_ DWORD Rva
)
{
    for (WORD i = 0; i < NumberOfSections; i++)
    {
        if (Rva >= SectionHeaders[i].VirtualAddress)
        {
            if (Rva < (SectionHeaders[i].VirtualAddress + SectionHeaders[i].SizeOfRawData))
            {
                return Rva - SectionHeaders[i].VirtualAddress + SectionHeaders[i].PointerToRawData;
            }
        }
    }

    return 0;
}

BOOL
KDUAPI
KduIsImage32Bit(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)Image + dosHeader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    return fileHeader->Machine == IMAGE_FILE_MACHINE_I386;
}

BOOL
KDUAPI
KduDumpPe32Header(
	_In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("File header is not 32 bit\n");

        return FALSE;
    }

    KDU_INFO("FileHeader\n");
    KDU_INFO("  Machine:%d\n", fileHeader->Machine);
    KDU_INFO("  NumberOfSections:%d\n", fileHeader->NumberOfSections);
    KDU_INFO("  TimeDateStamp:%u\n", fileHeader->TimeDateStamp);
    KDU_INFO("  PointerToSymbolTable:%u\n", fileHeader->PointerToSymbolTable);
    KDU_INFO("  NumberOfSymbols:%u\n", fileHeader->NumberOfSymbols);
    KDU_INFO("  SizeOfOptionalHeader:%d\n", fileHeader->SizeOfOptionalHeader);
    KDU_INFO("  Characteristics:%d\n", fileHeader->Characteristics);
    KDU_INFO("\n");

    PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;

    KDU_INFO("OptionalHeader\n");
    KDU_INFO("  Magic:%d\n", optionalHeader->Magic);
    KDU_INFO("  MajorLinkerVersion:%d\n", optionalHeader->MajorLinkerVersion);
    KDU_INFO("  MinorLinkerVersion:%d\n", optionalHeader->MinorLinkerVersion);
    KDU_INFO("  SizeOfCode:%u\n", optionalHeader->SizeOfCode);
    KDU_INFO("  SizeOfInitializedData:%u\n", optionalHeader->SizeOfInitializedData);
    KDU_INFO("  SizeOfUninitializedData:%u\n", optionalHeader->SizeOfUninitializedData);
    KDU_INFO("  AddressOfEntryPoint:0x%08X\n", optionalHeader->AddressOfEntryPoint);
    KDU_INFO("  BaseOfCode:0x%08X\n", optionalHeader->BaseOfCode);
    KDU_INFO("  BaseOfData:0x%08X\n", optionalHeader->BaseOfData);
    KDU_INFO("  ImageBase:0x%08X\n", optionalHeader->ImageBase);
    KDU_INFO("  SectionAlignment:%u\n", optionalHeader->SectionAlignment);
    KDU_INFO("  FileAlignment:%u\n", optionalHeader->FileAlignment);
    KDU_INFO("  MajorOperatingSystemVersion:%d\n", optionalHeader->MajorOperatingSystemVersion);
    KDU_INFO("  MinorOperatingSystemVersion:%d\n", optionalHeader->MinorOperatingSystemVersion);
    KDU_INFO("  MajorImageVersion:%d\n", optionalHeader->MajorImageVersion);
    KDU_INFO("  MinorImageVersion:%d\n", optionalHeader->MinorImageVersion);
    KDU_INFO("  MajorSubsystemVersion:%d\n", optionalHeader->MajorSubsystemVersion);
    KDU_INFO("  MinorSubsystemVersion:%d\n", optionalHeader->MinorSubsystemVersion);
    KDU_INFO("  Win32VersionValue:%u\n", optionalHeader->Win32VersionValue);
    KDU_INFO("  SizeOfImage:%u\n", optionalHeader->SizeOfImage);
    KDU_INFO("  SizeOfHeaders:%u\n", optionalHeader->SizeOfHeaders);
    KDU_INFO("  CheckSum:%u\n", optionalHeader->CheckSum);
    KDU_INFO("  Subsystem:%d\n", optionalHeader->Subsystem);
    KDU_INFO("  DllCharacteristics:%d\n", optionalHeader->DllCharacteristics);
    KDU_INFO("  SizeOfStackReserve:0x%08X\n", optionalHeader->SizeOfStackReserve);
    KDU_INFO("  SizeOfStackCommit:0x%08X\n", optionalHeader->SizeOfStackCommit);
    KDU_INFO("  SizeOfHeapReserve:0x%08X\n", optionalHeader->SizeOfHeapReserve);
    KDU_INFO("  SizeOfHeapCommit:0x%08X\n", optionalHeader->SizeOfHeapCommit);
    KDU_INFO("  LoaderFlags:%u\n", optionalHeader->LoaderFlags);
    KDU_INFO("  NumberOfRvaAndSizes:%u\n", optionalHeader->NumberOfRvaAndSizes);
    KDU_INFO("  DataDirectories\n");
    for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        PIMAGE_DATA_DIRECTORY dataDirectory = &optionalHeader->DataDirectory[i];

        KDU_INFO("    VirtualAddress:0x%08X Size:0x%08X\n", dataDirectory->VirtualAddress, dataDirectory->Size);
    }
    KDU_INFO("\n");

    return TRUE;
}

BOOL
KDUAPI
KduDumpPe64Header(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("File header is not 64 bit\n");

        return FALSE;
    }

    KDU_INFO("FileHeader\n");
    KDU_INFO("  Machine:%d\n", fileHeader->Machine);
    KDU_INFO("  NumberOfSections:%d\n", fileHeader->NumberOfSections);
    KDU_INFO("  TimeDateStamp:%u\n", fileHeader->TimeDateStamp);
    KDU_INFO("  PointerToSymbolTable:%u\n", fileHeader->PointerToSymbolTable);
    KDU_INFO("  NumberOfSymbols:%u\n", fileHeader->NumberOfSymbols);
    KDU_INFO("  SizeOfOptionalHeader:%d\n", fileHeader->SizeOfOptionalHeader);
    KDU_INFO("  Characteristics:%d\n", fileHeader->Characteristics);
    KDU_INFO("\n");

    PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&ntHeaders->OptionalHeader;

    KDU_INFO("OptionalHeader\n");
    KDU_INFO("  Magic:%d\n", optionalHeader->Magic);
    KDU_INFO("  MajorLinkerVersion:%d\n", optionalHeader->MajorLinkerVersion);
    KDU_INFO("  MinorLinkerVersion:%d\n", optionalHeader->MinorLinkerVersion);
    KDU_INFO("  SizeOfCode:%u\n", optionalHeader->SizeOfCode);
    KDU_INFO("  SizeOfInitializedData:%u\n", optionalHeader->SizeOfInitializedData);
    KDU_INFO("  SizeOfUninitializedData:%u\n", optionalHeader->SizeOfUninitializedData);
    KDU_INFO("  AddressOfEntryPoint:0x%08X\n", optionalHeader->AddressOfEntryPoint);
    KDU_INFO("  BaseOfCode:0x%08X\n", optionalHeader->BaseOfCode);
    KDU_INFO("  ImageBase:0x%016llX\n", optionalHeader->ImageBase);
    KDU_INFO("  SectionAlignment:%u\n", optionalHeader->SectionAlignment);
    KDU_INFO("  FileAlignment:%u\n", optionalHeader->FileAlignment);
    KDU_INFO("  MajorOperatingSystemVersion:%d\n", optionalHeader->MajorOperatingSystemVersion);
    KDU_INFO("  MinorOperatingSystemVersion:%d\n", optionalHeader->MinorOperatingSystemVersion);
    KDU_INFO("  MajorImageVersion:%d\n", optionalHeader->MajorImageVersion);
    KDU_INFO("  MinorImageVersion:%d\n", optionalHeader->MinorImageVersion);
    KDU_INFO("  MajorSubsystemVersion:%d\n", optionalHeader->MajorSubsystemVersion);
    KDU_INFO("  MinorSubsystemVersion:%d\n", optionalHeader->MinorSubsystemVersion);
    KDU_INFO("  Win32VersionValue:%u\n", optionalHeader->Win32VersionValue);
    KDU_INFO("  SizeOfImage:%u\n", optionalHeader->SizeOfImage);
    KDU_INFO("  SizeOfHeaders:%u\n", optionalHeader->SizeOfHeaders);
    KDU_INFO("  CheckSum:%u\n", optionalHeader->CheckSum);
    KDU_INFO("  Subsystem:%d\n", optionalHeader->Subsystem);
    KDU_INFO("  DllCharacteristics:%d\n", optionalHeader->DllCharacteristics);
    KDU_INFO("  SizeOfStackReserve:0x%016llX\n", optionalHeader->SizeOfStackReserve);
    KDU_INFO("  SizeOfStackCommit:0x%016llX\n", optionalHeader->SizeOfStackCommit);
    KDU_INFO("  SizeOfHeapReserve:0x%016llX\n", optionalHeader->SizeOfHeapReserve);
    KDU_INFO("  SizeOfHeapCommit:0x%016llX\n", optionalHeader->SizeOfHeapCommit);
    KDU_INFO("  LoaderFlags:%u\n", optionalHeader->LoaderFlags);
    KDU_INFO("  NumberOfRvaAndSizes:%u\n", optionalHeader->NumberOfRvaAndSizes);
    KDU_INFO("  DataDirectories\n");
    for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        PIMAGE_DATA_DIRECTORY dataDirectory = &optionalHeader->DataDirectory[i];

        KDU_INFO("    VirtualAddress:0x%08X Size:0x%08X\n", dataDirectory->VirtualAddress, dataDirectory->Size);
    }
    KDU_INFO("\n");

    return TRUE;
}

BOOL
KDUAPI
KduDumpPe32Sections(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    KDU_INFO("Sections\n");
    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        KDU_INFO("  Name:%s\n", sectionHeader->Name);
        KDU_INFO("  VirtualSize:0x%08X\n", sectionHeader->Misc.VirtualSize);
        KDU_INFO("  VirtualAddress:0x%08X\n", sectionHeader->VirtualAddress);
        KDU_INFO("  SizeOfRawData:0x%08X\n", sectionHeader->SizeOfRawData);
        KDU_INFO("  PointerToRawData:0x%08X\n", sectionHeader->PointerToRawData);
        KDU_INFO("  PointerToRelocations:0x%08X\n", sectionHeader->PointerToRelocations);
        KDU_INFO("  PointerToLinenumbers:0x%08X\n", sectionHeader->PointerToLinenumbers);
        KDU_INFO("  NumberOfRelocations:0x%08X\n", sectionHeader->NumberOfRelocations);
        KDU_INFO("  NumberOfLinenumbers:0x%08X\n", sectionHeader->NumberOfLinenumbers);
        KDU_INFO("  Characteristics:0x%08X\n", sectionHeader->Characteristics);
        KDU_INFO("\n");
    }

    return TRUE;
}

BOOL
KDUAPI
KduDumpPe64Sections(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    KDU_INFO("Sections\n");
    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        KDU_INFO("  Name:%s\n", sectionHeader->Name);
        KDU_INFO("  VirtualSize:0x%08X\n", sectionHeader->Misc.VirtualSize);
        KDU_INFO("  VirtualAddress:0x%08X\n", sectionHeader->VirtualAddress);
        KDU_INFO("  SizeOfRawData:0x%08X\n", sectionHeader->SizeOfRawData);
        KDU_INFO("  PointerToRawData:0x%08X\n", sectionHeader->PointerToRawData);
        KDU_INFO("  PointerToRelocations:0x%08X\n", sectionHeader->PointerToRelocations);
        KDU_INFO("  PointerToLinenumbers:0x%08X\n", sectionHeader->PointerToLinenumbers);
        KDU_INFO("  NumberOfRelocations:0x%08X\n", sectionHeader->NumberOfRelocations);
        KDU_INFO("  NumberOfLinenumbers:0x%08X\n", sectionHeader->NumberOfLinenumbers);
        KDU_INFO("  Characteristics:0x%08X\n", sectionHeader->Characteristics);
        KDU_INFO("\n");
    }

    return TRUE;
}

BOOL
KDUAPI
KduDumpPe32Section(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            KDU_INFO("Section\n");
            KDU_INFO("  Name:%s\n", sectionHeader->Name);
            KDU_INFO("  VirtualSize:0x%08X\n", sectionHeader->Misc.VirtualSize);
            KDU_INFO("  VirtualAddress:0x%08X\n", sectionHeader->VirtualAddress);
            KDU_INFO("  SizeOfRawData:0x%08X\n", sectionHeader->SizeOfRawData);
            KDU_INFO("  PointerToRawData:0x%08X\n", sectionHeader->PointerToRawData);
            KDU_INFO("  PointerToRelocations:0x%08X\n", sectionHeader->PointerToRelocations);
            KDU_INFO("  PointerToLinenumbers:0x%08X\n", sectionHeader->PointerToLinenumbers);
            KDU_INFO("  NumberOfRelocations:0x%08X\n", sectionHeader->NumberOfRelocations);
            KDU_INFO("  NumberOfLinenumbers:0x%08X\n", sectionHeader->NumberOfLinenumbers);
            KDU_INFO("  Characteristics:0x%08X\n", sectionHeader->Characteristics);
            KDU_INFO("\n");

            return TRUE;
        }
    }

    return FALSE;
}

BOOL
KDUAPI
KduDumpPe64Section(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            KDU_INFO("Section\n");
            KDU_INFO("  Name:%s\n", sectionHeader->Name);
            KDU_INFO("  VirtualSize:0x%08X\n", sectionHeader->Misc.VirtualSize);
            KDU_INFO("  VirtualAddress:0x%08X\n", sectionHeader->VirtualAddress);
            KDU_INFO("  SizeOfRawData:0x%08X\n", sectionHeader->SizeOfRawData);
            KDU_INFO("  PointerToRawData:0x%08X\n", sectionHeader->PointerToRawData);
            KDU_INFO("  PointerToRelocations:0x%08X\n", sectionHeader->PointerToRelocations);
            KDU_INFO("  PointerToLinenumbers:0x%08X\n", sectionHeader->PointerToLinenumbers);
            KDU_INFO("  NumberOfRelocations:0x%08X\n", sectionHeader->NumberOfRelocations);
            KDU_INFO("  NumberOfLinenumbers:0x%08X\n", sectionHeader->NumberOfLinenumbers);
            KDU_INFO("  Characteristics:0x%08X\n", sectionHeader->Characteristics);
            KDU_INFO("\n");

            return TRUE;
        }
    }

    return FALSE;
}

BOOL
KDUAPI
KduCollectPe32Sections(
    _In_ PVOID Image,
    _Out_ PLIST_ENTRY Sections
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    KduInitListHead(Sections);

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        PSECTION_ENTRY section = (PSECTION_ENTRY)calloc(1, sizeof(SECTION_ENTRY));

        section->SectionData = calloc(1, sectionHeader->SizeOfRawData);

        PBYTE sectionSource = (PBYTE)Image + sectionHeader->PointerToRawData;

        memcpy(&section->SectionHeader, sectionHeader, sizeof(IMAGE_SECTION_HEADER));
        memcpy(section->SectionData, sectionSource, sectionHeader->SizeOfRawData);

        KduInsertListTail(Sections, &section->ListEntry);
    }

    return TRUE;
}

BOOL
KDUAPI
KduCollectPe64Sections(
    _In_ PVOID Image,
    _Out_ PLIST_ENTRY Sections
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    KduInitListHead(Sections);

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        PSECTION_ENTRY section = (PSECTION_ENTRY)calloc(1, sizeof(SECTION_ENTRY));

        section->SectionData = calloc(1, sectionHeader->SizeOfRawData);

        PBYTE sectionSource = (PBYTE)Image + sectionHeader->PointerToRawData;

        memcpy(&section->SectionHeader, sectionHeader, sizeof(IMAGE_SECTION_HEADER));
        memcpy(section->SectionData, sectionSource, sectionHeader->SizeOfRawData);

        KduInsertListTail(Sections, &section->ListEntry);
    }

    return TRUE;
}

VOID
KDUAPI
KduFreeSections(
    _In_ PLIST_ENTRY Sections
)
{
    while (KduIsListEmpty(Sections) == FALSE)
    {
        PLIST_ENTRY entry = KduRemoveHeadList(Sections);

        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);

        free(section->SectionData);
        free(section);
    }

    KduInitListHead(Sections);
}

DWORD
KDUAPI
KduGetPe32PhysicalEntryOffset(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("File header is not 64 bit\n");

        return 0;
    }

    PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    WORD numberOfSections = fileHeader->NumberOfSections;

    DWORD offset = KduRvaToOffset(sectionHeaders, numberOfSections, optionalHeader->AddressOfEntryPoint);
    WORD section = KduRvaToSection(sectionHeaders, numberOfSections, optionalHeader->AddressOfEntryPoint);

    return offset - sectionHeaders[section].PointerToRawData;
}

DWORD
KDUAPI
KduGetPe64PhysicalEntryOffset(
    _In_ PVOID Image
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return FALSE;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return FALSE;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("File header is not 64 bit\n");

        return 0;
    }

    PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&ntHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    WORD numberOfSections = fileHeader->NumberOfSections;

    DWORD offset = KduRvaToOffset(sectionHeaders, numberOfSections, optionalHeader->AddressOfEntryPoint);
    WORD section = KduRvaToSection(sectionHeaders, numberOfSections, optionalHeader->AddressOfEntryPoint);

    return offset - sectionHeaders[section].PointerToRawData;
}

DWORD
KDUAPI
KduGetPe32PhysicalSectionOffset(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->PointerToRawData;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe64PhysicalSectionOffset(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->PointerToRawData;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe32PhysicalSectionSize(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");
    
        return 0;
    }
    
    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");
    
        return 0;
    }
    
    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;
    
    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");
    
        return 0;
    }
    
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));
    
    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];
    
        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {    
            return sectionHeader->SizeOfRawData;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe64PhysicalSectionSize(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->SizeOfRawData;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe32VirtualSectionOffset(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->VirtualAddress;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe64VirtualSectionOffset(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->VirtualAddress;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe32VirtualSectionSize(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->Misc.VirtualSize;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe64VirtualSectionSize(
    _In_ PVOID Image,
    _In_ LPCSTR SectionName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("Invalid architecture\n");

        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (WORD i = 0; i < fileHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = &sectionHeaders[i];

        if (strcmp(sectionHeader->Name, SectionName) == 0)
        {
            return sectionHeader->Misc.VirtualSize;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe32PhysicalExportOffset(
    _In_ PVOID Image,
    _In_ LPCSTR ExportName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        KDU_ERROR("File header is not 32 bit\n");

        return 0;
    }

    PIMAGE_OPTIONAL_HEADER32 optionalHeader = (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY dataDirectories = (PIMAGE_DATA_DIRECTORY)&optionalHeader->DataDirectory;
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS32));

    WORD numberOfSections = fileHeader->NumberOfSections;

    DWORD exportDirectoryRva = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirectorySize = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD exportDirectoryOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectoryRva);

    if (exportDirectoryOffset == -1)
    {
        KDU_ERROR("Invalid export directory offset\n");

        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)Image + exportDirectoryOffset);

    DWORD addressOfFunctionsOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfFunctions);
    DWORD addressOfNameOrdinalsOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfNameOrdinals);
    DWORD addressOfNamesOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfNames);

    if ((addressOfFunctionsOffset == -1) || (addressOfNameOrdinalsOffset == -1) || (addressOfNamesOffset == -1))
    {
        KDU_ERROR("Invalid export directory offsets\n");

        return 0;
    }

    PDWORD addressOfFunctions = (PDWORD)((PBYTE)Image + addressOfFunctionsOffset);
    PWORD addressOfNameOrdinals = (PWORD)((PBYTE)Image + addressOfNameOrdinalsOffset);
    PDWORD addressOfNames = (PDWORD)((PBYTE)Image + addressOfNamesOffset);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        DWORD currentNameOffset = KduRvaToOffset(sectionHeaders, numberOfSections, addressOfNames[i]);

        if (currentNameOffset == -1)
        {
            continue;
        }

        LPCSTR currentName = (LPCSTR)((PBYTE)Image + currentNameOffset);

        DWORD currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];

        if ((currentFunctionRva < (exportDirectoryRva + exportDirectorySize)) && (currentFunctionRva >= exportDirectoryRva))
        {
            continue;
        }

        if (strcmp(currentName, ExportName) == 0)
        {
            DWORD offset = KduRvaToOffset(sectionHeaders, numberOfSections, currentFunctionRva);
            WORD section = KduRvaToSection(sectionHeaders, numberOfSections, currentFunctionRva);

            return offset - sectionHeaders[section].PointerToRawData;
        }
    }

    return 0;
}

DWORD
KDUAPI
KduGetPe64PhysicalExportOffset(
    _In_ PVOID Image,
    _In_ LPCSTR ExportName
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Image;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KDU_ERROR("Invalid DOS signature\n");

        return 0;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)Image + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        KDU_ERROR("Invalid NT signature\n");

        return 0;
    }

    PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        KDU_ERROR("File header is not 64 bit\n");

        return 0;
    }

    PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)&ntHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY dataDirectories = (PIMAGE_DATA_DIRECTORY)&optionalHeader->DataDirectory;
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    WORD numberOfSections = fileHeader->NumberOfSections;

    DWORD exportDirectoryRva = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirectorySize = dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD exportDirectoryOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectoryRva);

    if (exportDirectoryOffset == 0)
    {
        KDU_ERROR("Invalid export directory offset\n");

        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)Image + exportDirectoryOffset);

    DWORD addressOfFunctionsOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfFunctions);
    DWORD addressOfNameOrdinalsOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfNameOrdinals);
    DWORD addressOfNamesOffset = KduRvaToOffset(sectionHeaders, numberOfSections, exportDirectory->AddressOfNames);

    if ((addressOfFunctionsOffset == 0) || (addressOfNameOrdinalsOffset == 0) || (addressOfNamesOffset == 0))
    {
        KDU_ERROR("Invalid export directory offsets\n");

        return 0;
    }

    PDWORD addressOfFunctions = (PDWORD)((PBYTE)Image + addressOfFunctionsOffset);
    PWORD addressOfNameOrdinals = (PWORD)((PBYTE)Image + addressOfNameOrdinalsOffset);
    PDWORD addressOfNames = (PDWORD)((PBYTE)Image + addressOfNamesOffset);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        DWORD currentNameOffset = KduRvaToOffset(sectionHeaders, numberOfSections, addressOfNames[i]);

        if (currentNameOffset == 0)
        {
            continue;
        }

        LPCSTR currentName = (LPCSTR)((PBYTE)Image + currentNameOffset);

        DWORD currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];

        if ((currentFunctionRva < (exportDirectoryRva + exportDirectorySize)) && (currentFunctionRva >= exportDirectoryRva))
        {
            continue;
        }

        if (strcmp(currentName, ExportName) == 0)
        {
            DWORD offset = KduRvaToOffset(sectionHeaders, numberOfSections, currentFunctionRva);
            WORD section = KduRvaToSection(sectionHeaders, numberOfSections, currentFunctionRva);

            return offset - sectionHeaders[section].PointerToRawData;
        }
    }

    return 0;
}