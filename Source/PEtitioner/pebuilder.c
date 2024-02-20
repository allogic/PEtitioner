#include <pebuilder.h>
#include <fileio.h>
#include <peutl.h>
#include <binalyzer.h>
#include <log.h>
#include <list.h>
#include <x64resolver.h>

static PBYTE sImage = NULL;
static DWORD sImageSize = 0;

VOID
KDUAPI
KduInitPeBuilder(
	_In_ LPCSTR ImagePath
)
{
    KduReadBinaryFile(ImagePath, &sImage, &sImageSize);
}

VOID
KDUAPI
KduAddNewSection(
    _In_ LPCSTR SectionName,
    _In_ DWORD SectionSize,
    _In_ DWORD Characteristics
)
{
    LIST_ENTRY sections;

    if (KduIsImage32Bit(sImage))
    {
        KduCollectPe32Sections(sImage, &sections);
    }
    else
    {
        KduCollectPe64Sections(sImage, &sections);
    }

    PSECTION_ENTRY prevSection = CONTAINING_RECORD(sections.Blink, SECTION_ENTRY, ListEntry);

    DWORD prevVirtualSize = prevSection->SectionHeader.Misc.VirtualSize;
    DWORD prevVirtualAddress = prevSection->SectionHeader.VirtualAddress;

    DWORD prevSizeOfRawData = prevSection->SectionHeader.SizeOfRawData;
    DWORD prevPointerToRawData = prevSection->SectionHeader.PointerToRawData;

    PSECTION_ENTRY section = (PSECTION_ENTRY)calloc(1, sizeof(SECTION_ENTRY));

    section->SectionData = calloc(1, SectionSize);

    memcpy(section->SectionHeader.Name, SectionName, strlen(SectionName));

    section->SectionHeader.Misc.VirtualSize = SectionSize;
    section->SectionHeader.VirtualAddress = prevVirtualAddress + KDU_ALIGN_PAGE_UP(prevVirtualSize);
    section->SectionHeader.SizeOfRawData = SectionSize;
    section->SectionHeader.PointerToRawData = prevPointerToRawData + prevSizeOfRawData;
    section->SectionHeader.Characteristics = Characteristics;

    KduInsertListTail(&sections, &section->ListEntry);

    KduUpdateSections(&sections);
    KduBuildPeImage(&sections);

    KduFreeSections(&sections);
}

VOID
KDUAPI
KduResizeSection(
    _In_ LPCSTR SectionName,
    _In_ DWORD SectionSize
)
{
    LIST_ENTRY sections;

    if (KduIsImage32Bit(sImage))
    {
        KduCollectPe32Sections(sImage, &sections);
    }
    else
    {
        KduCollectPe64Sections(sImage, &sections);
    }

    PSECTION_ENTRY firstSection = CONTAINING_RECORD(sections.Flink, SECTION_ENTRY, ListEntry);

    DWORD prevVirtualAddress = firstSection->SectionHeader.VirtualAddress;
    DWORD prevPointerToRawData = firstSection->SectionHeader.PointerToRawData;

    PLIST_ENTRY entry = sections.Flink;
    while (entry != &sections)
    {
        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);

        if (strcmp(section->SectionHeader.Name, SectionName) == 0)
        {
            PVOID newSectionData = calloc(1, SectionSize);

            memcpy(newSectionData, section->SectionData, SectionSize);

            free(section->SectionData);

            section->SectionHeader.Misc.VirtualSize = SectionSize;
            section->SectionHeader.VirtualAddress = prevVirtualAddress;
            section->SectionHeader.SizeOfRawData = SectionSize;
            section->SectionHeader.PointerToRawData = prevPointerToRawData;

            section->SectionData = newSectionData;

            prevVirtualAddress += SectionSize;
            prevPointerToRawData += SectionSize;
        }
        else
        {
            section->SectionHeader.VirtualAddress = prevVirtualAddress;
            section->SectionHeader.PointerToRawData = prevPointerToRawData;

            prevVirtualAddress += KDU_PAGE_SIZE;
            prevPointerToRawData += SectionSize;
        }

        entry = entry->Flink;
    }

    KduUpdateSections(&sections);
    KduBuildPeImage(&sections);

    KduFreeSections(&sections);
}

VOID
KDUAPI
KduCopyFunctionByPatternIntoSection(
    _In_ LPCSTR FunctionPattern,
    _In_ LPCSTR SectionName,
    _In_ DWORD FunctionOffset
)
{
    DWORD newPhysicalSectionOffset = 0;

    DWORD oldVirtualSectionOffset = 0;
    DWORD newVirtualSectionOffset = 0;

    if (KduIsImage32Bit(sImage))
    {
        newPhysicalSectionOffset = KduGetPe32PhysicalSectionOffset(sImage, SectionName);

        oldVirtualSectionOffset = KduGetPe32VirtualSectionOffset(sImage, ".text");
        newVirtualSectionOffset = KduGetPe32VirtualSectionOffset(sImage, SectionName);
    }
    else
    {
        newPhysicalSectionOffset = KduGetPe64PhysicalSectionOffset(sImage, SectionName);

        oldVirtualSectionOffset = KduGetPe64VirtualSectionOffset(sImage, ".text");
        newVirtualSectionOffset = KduGetPe64VirtualSectionOffset(sImage, SectionName);
    }

    DWORD physicalFunctionOffset = KduFindPhysicalOffsetByPattern(sImage, sImageSize, FunctionPattern);
    DWORD physicalFunctionSize = KduGetFunctionSize(sImage + physicalFunctionOffset);

    memcpy(sImage + newPhysicalSectionOffset + FunctionOffset, sImage + physicalFunctionOffset, physicalFunctionSize);

    KduResolveFunction(sImage, newPhysicalSectionOffset + FunctionOffset, physicalFunctionSize, oldVirtualSectionOffset, newVirtualSectionOffset);
}

VOID
KDUAPI
KduPatchFunctionByPatternWithInt3(
    _In_ LPCSTR FunctionPattern
)
{
    DWORD physicalFunctionOffset = KduFindPhysicalOffsetByPattern(sImage, sImageSize, FunctionPattern);
    DWORD physicalFunctionSize = KduGetFunctionSize(sImage + physicalFunctionOffset);

    memset(sImage + physicalFunctionOffset, 0xCC, physicalFunctionSize);
}

VOID
KDUAPI
KduUpdateSections(
    _In_ PLIST_ENTRY Sections
)
{
    WORD numberOfSections = (WORD)KduCountListEntries(Sections);
    DWORD pointerToRawData = 0;

    pointerToRawData += sizeof(IMAGE_DOS_HEADER);
    pointerToRawData += sizeof(IMAGE_DOS_STUB);
    pointerToRawData += sizeof(IMAGE_NT_HEADERS);
    pointerToRawData += sizeof(IMAGE_SECTION_HEADER) * numberOfSections;

    pointerToRawData = KDU_ALIGN_PAGE_UP(pointerToRawData);

    PLIST_ENTRY entry = Sections->Flink;
    while (entry != Sections)
    {
        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);
    
        section->SectionHeader.PointerToRawData = pointerToRawData;
    
        pointerToRawData += section->SectionHeader.SizeOfRawData;
        pointerToRawData = KDU_ALIGN_PAGE_UP(pointerToRawData);
    
        entry = entry->Flink;
    }

    if (KduIsImage32Bit(sImage))
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)sImage;
        PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)(sImage + dosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = &ntHeaders->OptionalHeader;
        PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

        fileHeader->NumberOfSections = numberOfSections;
    }
    else
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)sImage;
        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(sImage + dosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = &ntHeaders->OptionalHeader;
        PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

        fileHeader->NumberOfSections = numberOfSections;
    }
}

VOID
KDUAPI
KduBuildPeImage(
    _In_ PLIST_ENTRY Sections
)
{
    PLIST_ENTRY entry = NULL;

    DWORD imageSize = 0;
    DWORD imageOffset = 0;

    imageSize += sizeof(IMAGE_DOS_HEADER);
    imageSize += sizeof(IMAGE_DOS_STUB);
    imageSize += sizeof(IMAGE_NT_HEADERS);
    imageSize += sizeof(IMAGE_SECTION_HEADER) * KduCountListEntries(Sections);

    imageSize = KDU_ALIGN_PAGE_UP(imageSize);

    entry = Sections->Flink;
    while (entry != Sections)
    {
        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);

        imageSize += section->SectionHeader.SizeOfRawData;
        imageSize = KDU_ALIGN_PAGE_UP(imageSize);

        entry = entry->Flink;
    }

    if (KduIsImage32Bit(sImage))
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)sImage;
        PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)(sImage + dosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = &ntHeaders->OptionalHeader;
        PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

        optionalHeader->SizeOfImage = imageSize;
    }
    else
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)sImage;
        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(sImage + dosHeader->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = &ntHeaders->OptionalHeader;
        PIMAGE_FILE_HEADER fileHeader = &ntHeaders->FileHeader;

        optionalHeader->SizeOfImage = imageSize;
    }

    PBYTE imageBuffer = (PBYTE)calloc(1, imageSize);

    memcpy(imageBuffer + imageOffset, sImage + imageOffset, sizeof(IMAGE_DOS_HEADER));
    imageOffset += sizeof(IMAGE_DOS_HEADER);

    memcpy(imageBuffer + imageOffset, sImage + imageOffset, sizeof(IMAGE_DOS_STUB));
    imageOffset += sizeof(IMAGE_DOS_STUB);

    memcpy(imageBuffer + imageOffset, sImage + imageOffset, sizeof(IMAGE_NT_HEADERS));
    imageOffset += sizeof(IMAGE_NT_HEADERS);

    entry = Sections->Flink;
    while (entry != Sections)
    {
        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);

        memcpy(imageBuffer + imageOffset, &section->SectionHeader, sizeof(IMAGE_SECTION_HEADER));
        imageOffset += sizeof(IMAGE_SECTION_HEADER);

        entry = entry->Flink;
    }

    imageOffset = KDU_ALIGN_PAGE_UP(imageOffset);

    entry = Sections->Flink;
    while (entry != Sections)
    {
        PSECTION_ENTRY section = CONTAINING_RECORD(entry, SECTION_ENTRY, ListEntry);

        memcpy(imageBuffer + imageOffset, section->SectionData, section->SectionHeader.SizeOfRawData);
        imageOffset += section->SectionHeader.SizeOfRawData;
        imageOffset = KDU_ALIGN_PAGE_UP(imageOffset);

        entry = entry->Flink;
    }

    free(sImage);

    sImage = imageBuffer;
    sImageSize = imageSize;
}

VOID
KDUAPI
KduReleasePeBuilder(
    _In_ LPCSTR ImagePath
)
{
    KduWriteBinaryFile(ImagePath, sImage, sImageSize);

    free(sImage);

    sImage = NULL;
    sImageSize = 0;
}