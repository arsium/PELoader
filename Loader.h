#pragma once
#include "NTHeader.h"
/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||

|| THX TO ||
* https://github.com/adamhlt/Manual-DLL-Loader
* https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/
*/

typedef BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID); typedef DllMain* LPDllMain;
typedef VOID APIENTRY ExeEntry(void);

//This function is a rework of function of Sektor7 Malware Development Intermediate Section 2. PE madness
//with https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
__forceinline LPVOID __cdecl GetProcedureAddressByOrd(HMODULE hMod, UINT ord)
{
    DWORD_PTR pBaseAddr = (DWORD_PTR)hMod;
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);

    WORD ordinal = (WORD)ord & 0xFFFF;
    DWORD Base = pExportDirAddr->Base;

    if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
    {
        return NULL_PTR;
    }

    PVOID fct = (PVOID)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    return fct;
}

//This function is a rework of function of Sektor7 Malware Development Intermediate Section 2. PE madness
//with https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
__forceinline LPVOID __cdecl GetProcedureAddressByName(HMODULE hMod, char* sProcName)
{
    LPNTFREEVIRTUALMEMORY pNtFree = (LPNTFREEVIRTUALMEMORY)GetProcedureAddressNt("NtFreeVirtualMemory\0");

    DWORD_PTR pBaseAddr = (DWORD_PTR)hMod;
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++)
    {
        char* sTmpFuncName = (char*)(pBaseAddr + (DWORD_PTR)pFuncNameTbl[i]);

        if (CompareAnsi(sProcName, sTmpFuncName) == TRUE)
        {
            unsigned short nameOrdinal = ((unsigned short*)((unsigned long long)pBaseAddr + pExportDirAddr->AddressOfNameOrdinals))[i];
            unsigned int addr = ((unsigned int*)((unsigned long long)pBaseAddr + pExportDirAddr->AddressOfFunctions))[nameOrdinal];

            if (addr > pExportDataDir->VirtualAddress && addr < pExportDataDir->VirtualAddress + pExportDataDir->Size)
            {
                char* forwardStr = (char*)(pBaseAddr + addr);
                char* funcName = Separator(forwardStr);
                char* moduleName = ReverseSeparator(forwardStr);

                SIZE_T size = ((SIZE_T)(StringLengthA(moduleName) * sizeof(WCHAR) + 2));
                WCHAR* moduleUnicode = MallocCustom(&size);
                moduleUnicode = CharToWCharT(moduleName);
                PVOID modAddress = GetModuleBaseAddress(moduleUnicode);

                pNtFree((HANDLE)(-1), &moduleUnicode, &size, MEM_RELEASE);
                size = ((SIZE_T)StringLengthA(moduleName));
                pNtFree((HANDLE)(-1), &moduleName, &size, MEM_RELEASE);

                return GetProcedureAddressByName((HMODULE)modAddress, funcName);
            }
            else
            {
                return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
            }
        }
    }
    return NULL;
}

#define min(a,b)            (((a) < (b)) ? (a) : (b))

__forceinline NTSTATUS __cdecl Loader(BYTE* PEData, NTSTATUS* status, BOOL cloakHeader)
{
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = (LPNTALLOCATEVIRTUALMEMORY)GetProcedureAddressNt((char*)"NtAllocateVirtualMemory\0");
    LPNTWRITEVIRTUALMEMORY pNtWrite = (LPNTWRITEVIRTUALMEMORY)GetProcedureAddressNt((char*)"NtWriteVirtualMemory\0");
    LPLDRLOADDLL pLdrLoadDll = (LPLDRLOADDLL)GetProcedureAddressNt("LdrLoadDll\0");
    LPRTLINITUNICODESTRING pUnicodeString = (LPRTLINITUNICODESTRING)GetProcedureAddressNt("RtlInitUnicodeString\0");
    LPNTPROTECTVIRTUALMEMORY pNtProtect = (LPNTPROTECTVIRTUALMEMORY)GetProcedureAddressNt("NtProtectVirtualMemory\0");

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)PEData;
    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);

    DWORD_PTR sizeOfImage = (DWORD_PTR)pNtHeader->OptionalHeader.SizeOfImage;
    DWORD entryPointRVA = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    DWORD sizeOfHeaders = pNtHeader->OptionalHeader.SizeOfHeaders;

    BYTE* imageLoadAddress = (BYTE*)NULL;
    *status = pNtAllocate((HANDLE)(-1), &imageLoadAddress, 0, &sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (*status != NT_SUCCESS)
    {
        return *status;
    }

    *status = pNtWrite((HANDLE)(-1), imageLoadAddress, PEData, pNtHeader->OptionalHeader.SizeOfHeaders, 0);

    if (*status != NT_SUCCESS)
    {
        return *status;
    }

    if (cloakHeader)
    {
        PVOID ntdllBaseAddress = GetModuleBaseAddress(L"ntdll.dll\0");
        if (ntdllBaseAddress != NULL)
        {
            IMAGE_DOS_HEADER* pNtDllDosHeader = ((IMAGE_DOS_HEADER*)ntdllBaseAddress);
            IMAGE_NT_HEADERS* pNtDllHeader = ((IMAGE_NT_HEADERS*)ntdllBaseAddress + pNtDllDosHeader->e_lfanew);
            *status = pNtWrite((HANDLE)(-1), imageLoadAddress, ntdllBaseAddress, min(pNtDllHeader->OptionalHeader.SizeOfHeaders, sizeOfHeaders), 0);

            if (*status != NT_SUCCESS)
            {
                return *status;
            }
        }
    }

    IMAGE_SECTION_HEADER* firstSection = (IMAGE_SECTION_HEADER*)((DWORD_PTR)pNtHeader + 4 + sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)// ++i
    {
        IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((DWORD_PTR)firstSection + (i * sizeof(IMAGE_SECTION_HEADER)));
        BYTE* dest = imageLoadAddress + sec->VirtualAddress;
        if (firstSection[i].SizeOfRawData > 0)
        {
            *status = pNtWrite((HANDLE)(-1), dest, PEData + firstSection[i].PointerToRawData, firstSection[i].SizeOfRawData, 0);
            if (*status != NT_SUCCESS)
            {
                return *status;
            }
        }
    }

    IMAGE_IMPORT_DESCRIPTOR* importDescriptors = (IMAGE_IMPORT_DESCRIPTOR*)(imageLoadAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (int i = 0; importDescriptors[i].OriginalFirstThunk != 0; i++)//++i
    {
        BYTE* moduleName = imageLoadAddress + importDescriptors[i].Name;
        WCHAR* m = CharToWCharT((char*)moduleName);
        HMODULE importModuleAddr = GetModuleBaseAddress(m);

        if (importModuleAddr == NULL)
        {
            PVOID moduleAddress = NULL;
            UNICODE_STRING name = { 0 };
            pUnicodeString(&name, m);
            *status = pLdrLoadDll(NULL, NULL, &name, &moduleAddress);

            if (*status != NT_SUCCESS)
            {
                return *status;
            }
            else
            {
                importModuleAddr = moduleAddress;
            }
        }

        IMAGE_THUNK_DATA* lookupTable = (IMAGE_THUNK_DATA*)(imageLoadAddress + importDescriptors[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA* addressTable = (IMAGE_THUNK_DATA*)(imageLoadAddress + importDescriptors[i].FirstThunk);

        for (int i = 0; lookupTable[i].u1.AddressOfData != 0; ++i)
        {
            void* functionAddr = NULL;
            DWORD_PTR lookupAddr = lookupTable[i].u1.AddressOfData;

            if ((lookupAddr & IMAGE_ORDINAL_FLAG) == 0)
            {
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(imageLoadAddress + lookupAddr);
                char* funcName = (char*)&(image_import->Name);
                functionAddr = GetProcedureAddressByName(importModuleAddr, funcName);
            }
            else
            {
                UINT functionOrdinal = (UINT)IMAGE_ORDINAL(addressTable[i].u1.Ordinal);
                functionAddr = GetProcedureAddressByOrd(importModuleAddr, functionOrdinal);
            }
            /*if (functionAddr == NULL)
            {
                
            }*/
            addressTable[i].u1.Function = (DWORD_PTR)functionAddr;
        }
    }

    DWORD_PTR deltaVAReloc = ((DWORD_PTR)imageLoadAddress) - (DWORD_PTR)pNtHeader->OptionalHeader.ImageBase;

    if (imageLoadAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && deltaVAReloc != 0)
    {
        IMAGE_BASE_RELOCATION* pRelocTable = (IMAGE_BASE_RELOCATION*)(imageLoadAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (pRelocTable->VirtualAddress != 0)
        {
            DWORD sizeOfTable = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* reloc = (WORD*)(pRelocTable + 1);

            for (DWORD i = 0; i < sizeOfTable; ++i)
            {
                int type = reloc[i] >> 12;
                int offset = reloc[i] & 0x0fff;

                DWORD_PTR* addressToChange = (DWORD_PTR*)(imageLoadAddress + pRelocTable->VirtualAddress + offset);

                switch (type)
                {
                    case IMAGE_REL_BASED_HIGHLOW:
                        *addressToChange += deltaVAReloc;
                        break;
                    case IMAGE_REL_BASED_DIR64:
                        *addressToChange += deltaVAReloc;
                        break;
                    default:
                        break;
                }
            }
            pRelocTable = (IMAGE_BASE_RELOCATION*)(((DWORD_PTR)pRelocTable) + pRelocTable->SizeOfBlock);
        }
    }

    if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0 && pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
    {
        PIMAGE_TLS_DIRECTORY pImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)imageLoadAddress + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* pCallbackTable = (PIMAGE_TLS_CALLBACK*)pImageTLSDirectory->AddressOfCallBacks;

        while (*pCallbackTable != NULL_PTR)
        {
            PIMAGE_TLS_CALLBACK pImageCallback = *pCallbackTable;
            pImageCallback(PEData, DLL_PROCESS_ATTACH, NULL_PTR);
            pCallbackTable++;
        }
    }

    DWORD oldProtect;
    DWORD_PTR sizeOf = pNtHeader->OptionalHeader.SizeOfHeaders;
    pNtProtect((HANDLE)(-1), &imageLoadAddress, &sizeOf, PAGE_READONLY, &oldProtect);;

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        BYTE* dest = imageLoadAddress + firstSection[i].VirtualAddress;
        DWORD sectionFlag = firstSection[i].Characteristics;
        DWORD virtualMemFlag = 0;
        if (sectionFlag & IMAGE_SCN_MEM_EXECUTE)
        {
            virtualMemFlag = (sectionFlag & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else
        {
            virtualMemFlag = (sectionFlag & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }

        sizeOf = firstSection[i].Misc.VirtualSize;
        pNtProtect((HANDLE)(-1), &dest, &sizeOf, virtualMemFlag, &oldProtect);
    }

    DWORD_PTR callAddress = (DWORD_PTR)(imageLoadAddress + entryPointRVA);

    if (!(pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        ExeEntry* mainExe = (ExeEntry*)((DWORD_PTR)callAddress);
        mainExe();
    }
    else
    {
        DllMain* mainDll = (DllMain*)((DWORD_PTR)callAddress);
        mainDll(((HMODULE)callAddress), DLL_PROCESS_ATTACH, NULL);
    }

    return NT_SUCCESS;
}