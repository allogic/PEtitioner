#include <stdio.h>

#include <windows.h>

#include <core.h>
#include <log.h>
#include <fileio.h>
#include <peutl.h>
#include <pebuilder.h>
#include <binalyzer.h>

VOID
KDUAPI
KduPatchPe64Image(
    _In_ LPCSTR ImagePath)
{
    KduInitPeBuilder(ImagePath);

    KduAddNewSection(".text2", KDU_PAGE_SIZE, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);

    KduCopyFunctionByPatternIntoSection("\x40\x53\x48\x83\xec\x20\x33\xdb\x0f\x1f\x84\x00\x00\x00\x00\x00\x8b\xd3\x48\x8d\x0d\xd7\x11\x00\x00\xe8\x82\xff\xff\xff\xb9\xe8", ".text2", 0);
    //KduPatchFunctionByPatternWithInt3("\x40\x53\x48\x83\xec\x20\x33\xdb\x0f\x1f\x84\x00\x00\x00\x00\x00\x8b\xd3\x48\x8d\x0d\xd7\x11\x00\x00\xe8\x82\xff\xff\xff\xb9\xe8");

    //KduReleasePeBuilder(ImagePath);
}

INT main()
{
    KduPatchPe64Image("C:\\Data\\VisualStudio\\PEtitioner\\x64\\Release\\VictimUsr.exe");

    return 0;

    PVOID victimImage = 0;
    DWORD victimImageSize = 0;

    KduReadBinaryFile("C:\\Data\\VisualStudio\\KDU\\x64\\Release\\Shippo.exe", &victimImage, &victimImageSize);

    DWORD victimTextOffset = KduGetPe64PhysicalSectionOffset(victimImage, ".text");
    DWORD victimTextSize = KduGetPe64PhysicalSectionSize(victimImage, ".text");

    PVOID payloadImage = 0;
    DWORD payloadImageSize = 0;

    KduReadBinaryFile("C:\\Data\\VisualStudio\\KDU\\x64\\Release\\Sesshomaru.exe", &payloadImage, &payloadImageSize);

    DWORD payloadTextOffset = KduGetPe64PhysicalSectionOffset(payloadImage, ".text");
    DWORD payloadTextSize = KduGetPe64PhysicalSectionSize(payloadImage, ".text");

    DWORD victimTextScatchSpaceOffset = KduGetSectionScratchSpaceOffset(victimImage, victimTextOffset, KDU_ALIGN_PAGE_UP(victimTextSize));
    DWORD victimTextScatchSpaceSize = KduGetSectionScratchSpaceSize(victimImage, victimTextOffset, KDU_ALIGN_PAGE_UP(victimTextSize));

    DWORD victimEntryOffset = KduGetPe64PhysicalEntryOffset(victimImage);
    DWORD payloadAsmOffset = KduGetPe64PhysicalExportOffset(payloadImage, "payloadAsm");
    DWORD payloadCOffset = KduGetPe64PhysicalExportOffset(payloadImage, "payloadC");

    PVOID victimTextScatchSpace = (PVOID)((DWORD64)victimImage + victimTextScatchSpaceOffset);
    PVOID victimEntry = (PVOID)((DWORD64)victimImage + victimTextOffset + victimEntryOffset);
    PVOID payloadAsm = (PVOID)((DWORD64)payloadImage + payloadTextOffset + payloadAsmOffset);
    PVOID payloadC = (PVOID)((DWORD64)payloadImage + payloadTextOffset + payloadCOffset);

    DWORD victimEntrySize = KduGetFunctionSize(victimEntry);
    DWORD payloadAsmSize = KduGetFunctionSize(payloadAsm);
    DWORD payloadCSize = KduGetFunctionSize(payloadC);

    KduDumpHex(victimEntry, victimEntrySize, 32);
    printf("\n");
    printf("\n");
    KduDumpHex(payloadAsm, payloadAsmSize, 32);
    printf("\n");
    printf("\n");
    KduDumpHex(payloadC, payloadCSize, 32);
    printf("\n");
    printf("\n");

    //KduNopRange((PVOID)((DWORD64)victimImage + victimTextOffset), victimTextSize);
    //KduNopRange(victimTextScatchSpace, victimTextScatchSpaceSize);
    //KduNopRange(victimEntry, victimEntrySize);
    //KduNopRange(payloadAsm, payloadAsmSize);
    //KduNopRange(payloadC, payloadCSize);

    KduWriteBinaryFile("C:\\Data\\VisualStudio\\KDU\\x64\\Release\\Shippo.exe", victimImage, victimImageSize);
    //KduWriteBinaryFile("C:\\Data\\VisualStudio\\KDU\\x64\\Release\\Sesshomaru.exe", payloadImage, payloadImageSize);

    free(victimImage);
    free(payloadImage);

    return 0;
}