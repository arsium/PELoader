#pragma comment(linker, "/entry:main")
#include "Loader.h"

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
*/

NTSTATUS main(void)
{
    char rtlUnicode[] = "RtlInitUnicodeString\0";
    char ntOpen[] = "NtOpenFile\0";
    char ntClose[] = "NtClose\0";
    char ntQueryInformationFile[] = "NtQueryInformationFile\0";
    char ntAllocate[] = "NtAllocateVirtualMemory\0";
    char ntRead[] = "NtReadFile\0";

    LPRTLINITUNICODESTRING pRtlInitUnicode = (LPRTLINITUNICODESTRING)GetProcedureAddressNt(rtlUnicode);
    LPNTOPENFILE pNtOpen = (LPNTOPENFILE)GetProcedureAddressNt(ntOpen);;
    LPNTCLOSE pNtClose = (LPNTCLOSE)GetProcedureAddressNt(ntClose);
    LPNTQUERYINFORMATIONFILE pNtQueryInformationFile = (LPNTQUERYINFORMATIONFILE)GetProcedureAddressNt(ntQueryInformationFile);
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = (LPNTALLOCATEVIRTUALMEMORY)GetProcedureAddressNt(ntAllocate);
    LPNTREADFILE pNtRead = (LPNTREADFILE)GetProcedureAddressNt(ntRead);

    UNICODE_STRING objectName = { 0 };

#if defined(_WIN64)
    WCHAR filePath[] = L"\\??\\\\C:\\your_pe.dll\0";//or exe
#else
    WCHAR filePath[] = L"\\??\\\\C:\\your_pe.dll\0";//or exe

#endif
    pRtlInitUnicode(&objectName, filePath);

    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL_PTR;
    objectAttributes.ObjectName = &objectName;
    objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    objectAttributes.SecurityDescriptor = NULL_PTR;
    objectAttributes.SecurityQualityOfService = NULL_PTR;
    IO_STATUS_BLOCK statusBlock = { 0 };
    HANDLE handleToFile = NULL_PTR;

    NTSTATUS status = pNtOpen(&handleToFile, GENERIC_READ | SYNCHRONIZE, &objectAttributes, &statusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT);

    if (status != NT_SUCCESS)
        return status;

    FILE_STANDARD_INFORMATION fileInfo = { 0x0 };
    status = pNtQueryInformationFile(handleToFile, &statusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);

    if (status != NT_SUCCESS)
        return status;

    BYTE* peData = NULL_PTR;

#if defined(_WIN64)
    SIZE_T sizeFile = (SIZE_T)(fileInfo.EndOfFile.QuadPart + 1);
#else
    SIZE_T sizeFile = (SIZE_T)(fileInfo.EndOfFile.LowPart + 1);
#endif

    status = pNtAllocate((HANDLE)(-1), &peData, 0, &sizeFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != NT_SUCCESS)
        return status;

    LARGE_INTEGER liBytes = { 0x0 };

#if defined(_WIN64)
    status = pNtRead(handleToFile, NULL_PTR, NULL_PTR, NULL_PTR, &statusBlock, peData, (ULONG)(fileInfo.EndOfFile.QuadPart + 1), &liBytes, NULL_PTR);
#else
    status = pNtRead(handleToFile, NULL_PTR, NULL_PTR, NULL_PTR, &statusBlock, peData, (ULONG)(fileInfo.EndOfFile.LowPart + 1), &liBytes, NULL_PTR);
#endif

    if (status != NT_SUCCESS)
        return status;

    status = pNtClose(handleToFile);

    if (status != NT_SUCCESS)
        return status;

    status = NT_SUCCESS;

    return Loader(peData, &status, FALSE);
}