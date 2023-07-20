#pragma once

/*
   Author : Arsium Copyright (C) 2023
   Arsium. All Rights Reserved.

   The definition types below come from my personal reversed stuff or link below.
   This header aims to provide definitions for most symbols used in reverse & security in Windows world.
   This header may be incomplete, incorrect or outdated.
   More definions will come in the future (existing could be updated) and will be sorted.

   OS :         21h2 (Windows 10)
   Build :      19044.2486
   Verision :   10.0.19044

   Sources :
    * https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
    * https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    * https://github.com/processhacker/phnt
    * https://github.com/winsiderss/systeminformer/tree/master/phnt/include
    * https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
    * https://github.com/reactos/reactos
    * https://github.com/adamhlt/Manual-DLL-Loader
    * https://github.com/vxunderground/VX-API
    * https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
    * Sektor7 PE Madness
*/

#define NULL_PTR                                    ((void *)0)
#define NULL                                        ((void *)0)
#define far
#define near
#define FAR                 far
#define NEAR                near
#define DUMMYSTRUCTNAME
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
//#define __nullterminated
#define NTAPI __stdcall

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE  1

typedef void* PVOID;
typedef PVOID HANDLE;
typedef unsigned long DWORD;
typedef HANDLE HICON;
typedef unsigned short WORD;
typedef long LONG;
typedef long NTSTATUS;

#ifdef NT_SUCCESS
#undef NT_SUCCESS
#endif
#define NT_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH         ((NTSTATUS)0xC0000004L)
#define STATUS_PORT_NOT_SET                 ((NTSTATUS)0xC0000353L)
#define STATUS_NOT_ALL_ASSIGNED             ((NTSTATUS)0x00000106)

typedef unsigned short WCHAR;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

#ifdef UNICODE
typedef WCHAR TBYTE;
#else
typedef unsigned char TBYTE;
#endif

#ifdef UNICODE
typedef WCHAR TCHAR;
#else
typedef char TCHAR;
#endif

#if !defined(_M_IX86)
typedef unsigned __int64 ULONGLONG;
#else
typedef double ULONGLONG;
#endif

#if defined(_WIN64)
typedef unsigned __int64 ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

#if !defined(_M_IX86)
typedef __int64 LONGLONG;
#else
typedef double LONGLONG;
#endif

#if defined(_WIN64)
typedef __int64 LONG_PTR;
#else
typedef long LONG_PTR;
#endif

#ifdef _WIN64
typedef unsigned int UHALF_PTR;
#else
typedef unsigned short UHALF_PTR;
#endif

typedef int BOOL;
typedef unsigned char BYTE;
typedef BYTE BOOLEAN;
#define CALLBACK __stdcall
typedef char CCHAR;
typedef char CHAR;
typedef DWORD COLORREF;
#define CONST const

typedef unsigned __int64 DWORDLONG;
typedef ULONG_PTR DWORD_PTR;
typedef unsigned int DWORD32;
typedef unsigned __int64 DWORD64;
typedef float FLOAT;
typedef HANDLE HACCEL;
typedef float FLOAT;

#ifdef _WIN64
typedef int HALF_PTR;
#else
typedef short HALF_PTR;
#endif

typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HCOLORSPACE;
typedef HANDLE HCONV;
typedef HANDLE HCONVLIST;
typedef HICON HCURSOR;
typedef HANDLE HDC;
typedef HANDLE HDDEDATA;
typedef HANDLE HDESK;
typedef HANDLE HDROP;
typedef HANDLE HDWP;
typedef HANDLE HENHMETAFILE;
typedef int HFILE;
typedef HANDLE HFONT;
typedef HANDLE HGDIOBJ;
typedef HANDLE HGLOBAL;
typedef HANDLE HHOOK;
typedef HANDLE HINSTANCE;
typedef HANDLE HKEY;
typedef HANDLE HKL;
typedef HANDLE HLOCAL;
typedef HANDLE HMENU;
typedef HANDLE HMETAFILE;
typedef HINSTANCE HMODULE;
typedef HANDLE HMONITOR;   //if (WINVER >= 0x0500) 
typedef HANDLE HPALETTE;
typedef HANDLE HPEN;
typedef LONG HRESULT;
typedef HANDLE HRGN;
typedef HANDLE HRSRC;
typedef HANDLE HSZ;
typedef HANDLE WINSTA;
typedef HANDLE HWND;
typedef int INT;

#if defined(_WIN64) 
typedef __int64 INT_PTR;
#else 
typedef int INT_PTR;
#endif

typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef signed __int64 INT64;
typedef WORD LANGID;
typedef DWORD LCID;
typedef DWORD LCTYPE;
typedef DWORD LGRPID;

typedef signed int LONG32;
typedef __int64 LONG64;
typedef LONG_PTR LPARAM;
typedef BOOL far* LPBOOL;
typedef BYTE far* LPBYTE;
typedef DWORD* LPCOLORREF;
typedef CONST CHAR* LPCSTR;     //__nullterminated

typedef CONST WCHAR* LPCWSTR;

#ifdef UNICODE
typedef LPCWSTR LPCTSTR;
#else
typedef LPCSTR LPCTSTR;
#endif

typedef CONST void* LPCVOID;
typedef DWORD* LPDWORD;
typedef HANDLE* LPHANDLE;
typedef int* LPINT;
typedef long* LPLONG;
typedef CHAR* LPSTR;

typedef WCHAR* LPWSTR;

#ifdef UNICODE
typedef LPWSTR LPTSTR;
#else
typedef LPSTR LPTSTR;
#endif

typedef void* LPVOID;
typedef WORD* LPWORD;
typedef LONG_PTR LRESULT;
typedef BOOL* PBOOL;
typedef BOOLEAN* PBOOLEAN;
typedef BYTE* PBYTE;
typedef CHAR* PCHAR;
typedef CONST CHAR* PCSTR;

#ifdef UNICODE
typedef LPCWSTR PCTSTR;
#else
typedef LPCSTR PCTSTR;
#endif

typedef CONST WCHAR* PCWSTR;
typedef DWORD* PDWORD;
typedef DWORDLONG* PDWORDLONG;
typedef DWORD_PTR* PDWORD_PTR;
typedef DWORD32* PDWORD32;
typedef DWORD64* PDWORD64;
typedef FLOAT* PFLOAT;

#ifdef _WIN64
typedef HALF_PTR* PHALF_PTR;
#else
typedef HALF_PTR* PHALF_PTR;
#endif

typedef HANDLE* PHANDLE;
typedef HKEY* PHKEY;
typedef int* PINT;
typedef INT_PTR* PINT_PTR;
typedef INT8* PINT8;
typedef INT16* PINT16;
typedef INT32* PINT32;
typedef INT64* PINT64;
typedef PDWORD PLCID;
typedef LONG* PLONG;
typedef LONGLONG* PLONGLONG;
typedef LONG_PTR* PLONG_PTR;
typedef LONG32* PLONG32;
typedef LONG64* PLONG64;

#if defined(_WIN64)
#define POINTER_32 __ptr32
#else
#define POINTER_32
#endif

#if (_MSC_VER >= 1300)
#define POINTER_64 __ptr64
#else
#define POINTER_64
#endif

#define POINTER_SIGNED __sptr
#define POINTER_UNSIGNED __uptr

#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#endif
#if (_MSC_VER >= 1915) && !defined(MIDL_PASS) && !defined(SORTPP_PASS) && !defined(RC_INVOKED)
#define DECLSPEC_NOINITALL __pragma(warning(push)) __pragma(warning(disable:4845)) __declspec(no_init_all) __pragma(warning(pop))
#endif

#ifdef UNICODE
typedef LPWSTR PTSTR;
#else typedef LPSTR PTSTR;
#endif

typedef UCHAR* PUCHAR;

#ifdef _WIN64
typedef UHALF_PTR* PUHALF_PTR;
#else
typedef UHALF_PTR* PUHALF_PTR;
#endif

typedef unsigned __int64 QWORD;
typedef HANDLE SC_HANDLE;
typedef LPVOID SC_LOCK;
typedef HANDLE SERVICE_STATUS_HANDLE;
typedef short SHORT;
typedef ULONG_PTR SIZE_T;
typedef LONG_PTR SSIZE_T;

typedef SHORT* PSHORT;
typedef SIZE_T* PSIZE_T;
typedef SSIZE_T* PSSIZE_T;
typedef CHAR* PSTR;
typedef TBYTE* PTBYTE;
typedef TCHAR* PTCHAR;

typedef unsigned int UINT;

#if defined(_WIN64)
typedef unsigned __int64 UINT_PTR;
#else
typedef unsigned int UINT_PTR;
#endif

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned __int64 UINT64;
typedef unsigned long ULONG;

typedef unsigned int ULONG32;
typedef unsigned __int64 ULONG64;

typedef UINT* PUINT;
typedef UINT_PTR* PUINT_PTR;
typedef UINT8* PUINT8;
typedef UINT16* PUINT16;
typedef UINT32* PUINT32;
typedef UINT64* PUINT64;
typedef ULONG* PULONG;
typedef ULONGLONG* PULONGLONG;
typedef ULONG_PTR* PULONG_PTR;
typedef ULONG32* PULONG32;
typedef ULONG64* PULONG64;
typedef USHORT* PUSHORT;
typedef WCHAR* PWCHAR;
typedef WORD* PWORD;
typedef WCHAR* PWSTR;

typedef CHAR* LPCH, * PCH;
typedef const CHAR* LPCCH, * PCCH;
typedef char* BSTR;

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef LONGLONG USN;
#define VOID void
#define WINAPI __stdcall
typedef UINT_PTR WPARAM;

#define APIENTRY WINAPI
typedef WORD ATOM;
typedef int (FAR WINAPI* FARPROC)(void);

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG  HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;
typedef LARGE_INTEGER* PLARGE_INTEGER;


typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;
typedef ULARGE_INTEGER* PULARGE_INTEGER;

typedef struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
}FILETIME, * PFILETIME;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _GUID
{
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    UCHAR Data4[0x8];
}GUID, * PGUID;

typedef struct _LUID
{
    DWORD LowPart;
    LONG HighPart;
}LUID, * PLUID;

typedef struct _ROOT_INFO_LUID
{
    DWORD LowPart;
    LONG HighPart;
}ROOT_INFO_LUID, * PROOT_INFO_LUID;

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, * PM128A;

typedef struct _FILE_ID_128 {
    BYTE Identifier[16];
} FILE_ID_128, * PFILE_ID_128;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, * PSTRING;

typedef struct _STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    DWORD* Buffer;
}STRING32, * PSTRING32;

typedef struct _STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    QWORD* Buffer;
}STRING64, * PSTRING64;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct LIST_ENTRY32
{
    DWORD Flink;
    DWORD Blink;
}LIST_ENTRY32, * PLIST_ENTRY32;

typedef struct _LIST_ENTRY64
{
    QWORD Flink;
    QWORD Blink;
}LIST_ENTRY64, * PLIST_ENTRY64;

typedef struct _PEB_LDR_DATA
{
    ULONG                  Length;
    BOOLEAN                Initialized;
    PVOID                  SsHandle;
    LIST_ENTRY             InLoadOrderModuleList;
    LIST_ENTRY             InMemoryOrderModuleList;
    LIST_ENTRY             InInitializationOrderModuleList;
    PVOID                  EntryInProgress;
    UCHAR                  ShutdownInProgress;
    PVOID                  ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_ENTRY
{
    LIST_ENTRY             InLoadOrderModuleList;
    LIST_ENTRY             InMemoryOrderModuleList;
    LIST_ENTRY             InInitializationOrderModuleList;
    PVOID                  BaseAddress;
    PVOID                  EntryPoint;
    ULONG                  SizeOfImage;
    UNICODE_STRING         FullDllName;
    UNICODE_STRING         BaseDllName;
    ULONG                  Flags;
    WORD                   LoadCount;
    WORD                   TlsIndex;
    LIST_ENTRY             HashLinks;
    ULONG                  TimeDateStamp;
    HANDLE                 ActivationContext;
    PVOID                  PatchInformation;
    LIST_ENTRY             ForwarderLinks;
    LIST_ENTRY             ServiceTagLinks;
    LIST_ENTRY             StaticLinks;
    PVOID                  ContextInformation;
    ULONG_PTR              OriginalBase;
    LARGE_INTEGER          LoadTime;
} LDR_DATA_ENTRY, * PLDR_DATA_ENTRY;//_LDR_MODULE

typedef struct _RTL_BITMAP
{
    ULONG  SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    STRING DosPath;//UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING     DosPath;
    PVOID              Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_PEB
{
    ULONG                      AllocationSize;
    ULONG                      Size;
    ULONG                      Flags;
    ULONG                      DebugFlags;
    HANDLE                     ConsoleHandle;
    ULONG                      ConsoleFlags;
    HANDLE                     hStdInput;
    HANDLE                     hStdOutput;
    HANDLE                     hStdError;
    CURDIR                     CurrentDirectory;
    UNICODE_STRING             DllPath;
    UNICODE_STRING             ImagePathName;
    UNICODE_STRING             CommandLine;
    PWSTR                      Environment;
    ULONG                      dwX;
    ULONG                      dwY;
    ULONG                      dwXSize;
    ULONG                      dwYSize;
    ULONG                      dwXCountChars;
    ULONG                      dwYCountChars;
    ULONG                      dwFillAttribute;
    ULONG                      dwFlags;
    ULONG                      wShowWindow;
    UNICODE_STRING             WindowTitle;
    UNICODE_STRING             Desktop;
    UNICODE_STRING             ShellInfo;
    UNICODE_STRING             RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR    DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS_PEB, * PRTL_USER_PROCESS_PARAMETERS_PEB;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    WORD                               Type;
    WORD                               CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY                         ProcessLocksList;
    DWORD                              EntryCount;
    DWORD                              ContentionCount;
    DWORD                              Flags;
    WORD                               CreatorBackTraceIndexHigh;
    WORD                               Identifier;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, * PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _PEB
{                                                                 /* win32/win64 */
    BOOLEAN                        InheritedAddressSpace;             /* 000/000 */
    BOOLEAN                        ReadImageFileExecOptions;          /* 001/001 */
    BOOLEAN                        BeingDebugged;                     /* 002/002 */
    BOOLEAN                        SpareBool;                         /* 003/003 */
    HANDLE                         Mutant;                            /* 004/008 */
    PVOID                          ImageBaseAddress;                  /* 008/010 */
    PPEB_LDR_DATA                  LdrData;
    RTL_USER_PROCESS_PARAMETERS_PEB* ProcessParameters;               /* 010/020 */
    PVOID                          SubSystemData;                     /* 014/028 */
    HANDLE                         ProcessHeap;                       /* 018/030 */
    PRTL_CRITICAL_SECTION          FastPebLock;                       /* 01c/038 */
    PVOID /*PPEBLOCKROUTINE*/      FastPebLockRoutine;                /* 020/040 */
    PVOID /*PPEBLOCKROUTINE*/      FastPebUnlockRoutine;              /* 024/048 */
    ULONG                          EnvironmentUpdateCount;            /* 028/050 */
    PVOID                          KernelCallbackTable;               /* 02c/058 */
    ULONG                          Reserved[2];                       /* 030/060 */
    PVOID /*PPEB_FREE_BLOCK*/      FreeList;                          /* 038/068 */
    ULONG                          TlsExpansionCounter;               /* 03c/070 */
    PRTL_BITMAP                    TlsBitmap;                         /* 040/078 */
    ULONG                          TlsBitmapBits[2];                  /* 044/080 */
    PVOID                          ReadOnlySharedMemoryBase;          /* 04c/088 */
    PVOID                          ReadOnlySharedMemoryHeap;          /* 050/090 */
    PVOID* ReadOnlyStaticServerData;          /* 054/098 */
    PVOID                          AnsiCodePageData;                  /* 058/0a0 */
    PVOID                          OemCodePageData;                   /* 05c/0a8 */
    PVOID                          UnicodeCaseTableData;              /* 060/0b0 */
    ULONG                          NumberOfProcessors;                /* 064/0b8 */
    ULONG                          NtGlobalFlag;                      /* 068/0bc */
    LARGE_INTEGER                  CriticalSectionTimeout;            /* 070/0c0 */
    ULONG_PTR                      HeapSegmentReserve;                /* 078/0c8 */
    ULONG_PTR                      HeapSegmentCommit;                 /* 07c/0d0 */
    ULONG_PTR                      HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    ULONG_PTR                      HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    ULONG                          NumberOfHeaps;                     /* 088/0e8 */
    ULONG                          MaximumNumberOfHeaps;              /* 08c/0ec */
    PVOID* ProcessHeaps;                      /* 090/0f0 */
    PVOID                          GdiSharedHandleTable;              /* 094/0f8 */
    PVOID                          ProcessStarterHelper;              /* 098/100 */
    PVOID                          GdiDCAttributeList;                /* 09c/108 */
    PVOID                          LoaderLock;                        /* 0a0/110 */
    ULONG                          OSMajorVersion;                    /* 0a4/118 */
    ULONG                          OSMinorVersion;                    /* 0a8/11c */
    ULONG                          OSBuildNumber;                     /* 0ac/120 */
    ULONG                          OSPlatformId;                      /* 0b0/124 */
    ULONG                          ImageSubSystem;                    /* 0b4/128 */
    ULONG                          ImageSubSystemMajorVersion;        /* 0b8/12c */
    ULONG                          ImageSubSystemMinorVersion;        /* 0bc/130 */
    ULONG                          ImageProcessAffinityMask;          /* 0c0/134 */
    HANDLE                         GdiHandleBuffer[28];               /* 0c4/138 */
    ULONG                          unknown[6];                        /* 134/218 */
    PVOID                          PostProcessInitRoutine;            /* 14c/230 */
    PRTL_BITMAP                    TlsExpansionBitmap;                /* 150/238 */
    ULONG                          TlsExpansionBitmapBits[32];        /* 154/240 */
    ULONG                          SessionId;                         /* 1d4/2c0 */
    ULARGE_INTEGER                 AppCompatFlags;                    /* 1d8/2c8 */
    ULARGE_INTEGER                 AppCompatFlagsUser;                /* 1e0/2d0 */
    PVOID                          ShimData;                          /* 1e8/2d8 */
    PVOID                          AppCompatInfo;                     /* 1ec/2e0 */
    UNICODE_STRING                 CSDVersion;                        /* 1f0/2e8 */
    PVOID                          ActivationContextData;             /* 1f8/2f8 */
    PVOID                          ProcessAssemblyStorageMap;         /* 1fc/300 */
    PVOID                          SystemDefaultActivationData;       /* 200/308 */
    PVOID                          SystemAssemblyStorageMap;          /* 204/310 */
    ULONG_PTR                      MinimumStackCommit;                /* 208/318 */
    PVOID* FlsCallback;                       /* 20c/320 */
    LIST_ENTRY                     FlsListHead;                       /* 210/328 */
    PRTL_BITMAP                    FlsBitmap;                         /* 218/338 */
    ULONG                          FlsBitmapBits[4];                  /* 21c/340 */
} PEB, * PPEB;

//-----------------------------------------------------------------------------------

#define IMAGE_DOS_SIGNATURE                                    0x5A4D      //MZ
#define IMAGE_NT_SIGNATURE                                     0x50450000  //PE00

#define IMAGE_SIZEOF_FILE_HEADER                               20
#define IMAGE_SIZEOF_SECTION_HEADER                            40
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES                       16
#define IMAGE_SIZEOF_SHORT_NAME                                8

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC                          0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC                          0x20b

typedef enum _PE_MAGIC // uint16_t
{
    PE_ROM_IMAGE = 0x107,
    PE_32BIT = 0x10b,
    PE_64BIT = 0x20b
}PE_MAGIC, * PPE_MAGIC;

#define IMAGE_ORDINAL_FLAG64                                   0x8000000000000000
#define IMAGE_ORDINAL_FLAG32                                   0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define IMAGE_DIRECTORY_ENTRY_EXPORT                           0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT                           1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE                         2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION                        3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY                         4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC                        5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG                            6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                     7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR                        8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS                              9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                      10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                     11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT                              12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                     13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR                   14   // COM Runtime descriptor

#define DLL_PROCESS_ATTACH   1    
#define DLL_THREAD_ATTACH    2    
#define DLL_THREAD_DETACH    3    
#define DLL_PROCESS_DETACH   0    

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001
#define IMAGE_FILE_MACHINE_I386              0x014c// Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162
#define IMAGE_FILE_MACHINE_R4000             0x0166  
#define IMAGE_FILE_MACHINE_R10000            0x0168 
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  
#define IMAGE_FILE_MACHINE_SH3               0x01a2 
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4
#define IMAGE_FILE_MACHINE_SH4               0x01a6
#define IMAGE_FILE_MACHINE_SH5               0x01a8
#define IMAGE_FILE_MACHINE_ARM               0x01c0
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200// Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466
#define IMAGE_FILE_MACHINE_AXP64             _IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC
#define IMAGE_FILE_MACHINE_AMD64             0x8664// AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041
#define IMAGE_FILE_MACHINE_ARM64             0xAA64
#define IMAGE_FILE_MACHINE_CEE               0xC0EE
#define IMAGE_FILE_MACHINE_RISCV32           0x5032
#define IMAGE_FILE_MACHINE_RISCV64           0x5064
#define IMAGE_FILE_MACHINE_RISCV128          0x5128

#define IMAGE_SUBSYSTEM_UNKNOWN                     0
#define IMAGE_SUBSYSTEM_NATIVE                      1  // #define IMAGE doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI                 2  // #define IMAGE runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI                 3  // #define IMAGE runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI                     5  // #define IMAGE runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI                   7  // #define IMAGE runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS              8  // #define IMAGE is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI              9  // #define IMAGE runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION             10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          12
#define IMAGE_SUBSYSTEM_EFI_ROM                     13
#define IMAGE_SUBSYSTEM_XBOX                        14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG           17

#define IMAGE_LIBRARY_PROCESS_INIT                          0x0001     // Reserved.
#define IMAGE_LIBRARY_PROCESS_TERM                          0x0002     // Reserved.
#define IMAGE_LIBRARY_THREAD_INIT                           0x0004     // Reserved.
#define IMAGE_LIBRARY_THREAD_TERM                           0x0008     // Reserved.

#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA                                    0x0020//64-bit  
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE                                       0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY                                    0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT                                          0x0100// DEP
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION                                       0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                                             0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND                                            0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER                                       0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER                                         0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF                                           0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE                              0x8000
#define IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT                                      0x01
#define IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE                          0x02
#define IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE      0x04
#define IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC                  0x08
#define IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1                                  0x10
#define IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2                                  0x20

#define IMAGE_FILE_RELOCS_STRIPPED              0x0001  // Relocation info stripped from file.
#define IMAGEIMAGE_FILE_EXECUTABLE_IMAGE        0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED           0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED          0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM            0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE          0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO            0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE                0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED               0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP      0x0400  // If #define IMAGE is on removable media copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP            0x0800  // If #define IMAGE is on Net copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                       0x1000  // System File.
#define IMAGE_FILE_DLL                          0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY               0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI            0x8000  // Bytes of machine word are reversed.

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _RICH_HEADER
{
    DWORD e_magic__DanS;
    DWORD e_align[0x3];
    DWORD e_entry_id0__00937809;
    DWORD e_entry_count0__51;
    DWORD e_entry_id1__00010000;
    DWORD e_entry_count1__135;
    DWORD e_entry_id2__00fd6b14;
    DWORD e_entry_count2__1;
    DWORD e_entry_id3__01006b14;
    DWORD e_entry_count3__1;
    DWORD e_entry_id4__01036b14;
    DWORD e_entry_count4__50;
    DWORD e_entry_id5__01056b14;
    DWORD e_entry_count5__94;
    DWORD e_entry_id6__010e6b14;
    DWORD e_entry_count6__568;
    DWORD e_entry_id7__01046b14;
    DWORD e_entry_count7__75;
    DWORD e_entry_id8__00ff6b14;
    DWORD e_entry_count8__1;
    DWORD e_entry_id9__01026b14;
    DWORD e_entry_count9__1;
    char e_magic[0x4];
    DWORD e_checksum;
}RICH_HEADER, * PRICH_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
#define ALIGNMENT_MACHINE
#define UNALIGNED __unaligned
#if defined(_WIN64)
#define UNALIGNED64 __unaligned
#else
#define UNALIGNED64
#endif
#else
#undef ALIGNMENT_MACHINE
#define UNALIGNED
#define UNALIGNED64
#endif

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_SCN_TYPE_REG                      0x00000000     // Reserved.
#define IMAGE_SCN_TYPE_DSECT                    0x00000001     // Reserved.
#define IMAGE_SCN_TYPE_NOLOAD                   0x00000002     // Reserved.
#define IMAGE_SCN_TYPE_GROUP                    0x00000004     // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                   0x00000008     // Reserved.
#define IMAGE_SCN_TYPE_COPY                     0x00000010     // Reserved.

#define IMAGE_SCN_CNT_CODE                      0x00000020     // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA          0x00000040     // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA        0x00000080     // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                     0x00000100     // Reserved.
#define IMAGE_SCN_LNK_INFO                      0x00000200     // Section contains comments or some other type of information.
#define IMAGE_SCN_TYPE_OVER                     0x00000400     // Reserved.
#define IMAGE_SCN_LNK_REMOVE                    0x00000800     // Section contents will not become part of #define IMAGE.
#define IMAGE_SCN_LNK_COMDAT                    0x00001000     // Section contents comdat.
//                    0x00002000  // Reserved.
//#define IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC             0x00004000     // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                         0x00008000     // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                   0x00008000
//#define IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE                 0x00020000
#define IMAGE_SCN_MEM_16BIT                     0x00020000
#define IMAGE_SCN_MEM_LOCKED                    0x00040000
#define IMAGE_SCN_MEM_PRELOAD                   0x00080000

#define IMAGE_SCN_ALIGN_1BYTES                  0x00100000
#define IMAGE_SCN_ALIGN_2BYTES                  0x00200000
#define IMAGE_SCN_ALIGN_4BYTES                  0x00300000
#define IMAGE_SCN_ALIGN_8BYTES                  0x00400000
#define IMAGE_SCN_ALIGN_16BYTES                 0x00500000     // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES                 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES                 0x00700000
#define IMAGE_SCN_ALIGN_128BYTES                0x00800000
#define IMAGE_SCN_ALIGN_256BYTES                0x00900000
#define IMAGE_SCN_ALIGN_512BYTES                0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES               0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES               0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES               0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES               0x00E00000
// Unused                                     0x00F00000
#define IMAGE_SCN_ALIGN_MASK                    0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL               0x01000000     // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE               0x02000000     // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED                0x04000000     // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED                 0x08000000     // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                    0x10000000     // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                   0x20000000     // Section is executable.
#define IMAGE_SCN_MEM_READ                      0x40000000     // Section is readable.
#define IMAGE_SCN_MEM_WRITE                     0x80000000     // Section is writeable.
#define IMAGE_SCN_SCALE_INDEX                   0x00000001      // Tls index is scaled*/

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress; //always virtualSize
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;

#define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef enum _IMPORT_OBJECT_NAME_TYPE // int32_t
{
    IMPORT_OBJECT_ORDINAL = 0x0,
    IMPORT_OBJECT_NAME = 0x1,
    IMPORT_OBJECT_NAME_NO_PREFIX = 0x2,
    IMPORT_OBJECT_NAME_UNDECORATE = 0x3,
    IMPORT_OBJECT_NAME_EXPORTAS = 0x4
}IMPORT_OBJECT_NAME_TYPE, * PIMPORT_OBJECT_NAME_TYPE;

typedef enum _IMPORT_OBJECT_TYPE // int32_t
{
    IMPORT_OBJECT_CODE = 0x0,
    IMPORT_OBJECT_DATA = 0x1,
    IMPORT_OBJECT_CONST = 0x2
}IMPORT_OBJECT_TYPE, * PIMPORT_OBJECT_TYPE;

#define IMPORT_OBJECT_HDR_SIG2  0xffff

typedef struct _IMPORT_OBJECT_HEADER
{
    USHORT Sig1;
    USHORT Sig2;
    USHORT Version;
    USHORT Machine;
    DWORD TimeDateStamp;
    DWORD SizeOfData;
    union
    {
        USHORT Ordinal;
        USHORT Hint;
    } __inner6;
    union
    {
        USHORT Type;
        USHORT NameType;
        USHORT Reserved;
    } __bitfield18;
}IMPORT_OBJECT_HEADER, * PIMPORT_OBJECT_HEADER;

//@[comment("MVI_tracked")]
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE 
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32* PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;         // PDWORD
    ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
    DWORD SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

} IMAGE_TLS_DIRECTORY64;

typedef IMAGE_TLS_DIRECTORY64* PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;             // PDWORD
    DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32* PIMAGE_TLS_DIRECTORY32;

typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK) (
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
    );

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED* PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64            IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64           PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC        IMAGE_NT_OPTIONAL_HDR64_MAGIC

#define IMAGE_ORDINAL_FLAG                 IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal)             IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64                 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64                PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)     IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef IMAGE_TLS_DIRECTORY64              IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64             PIMAGE_TLS_DIRECTORY;

#else
typedef IMAGE_NT_HEADERS32                 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32            IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32           PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC        IMAGE_NT_OPTIONAL_HDR32_MAGIC

#define IMAGE_ORDINAL_FLAG                 IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal)             IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32                 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32                PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)     IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef IMAGE_TLS_DIRECTORY32              IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32             PIMAGE_TLS_DIRECTORY;
#endif

#define IMAGE_DEBUG_TYPE_UNKNOWN        0x0
#define IMAGE_DEBUG_TYPE_COFF           0x1
#define IMAGE_DEBUG_TYPE_CODEVIEW       0x2
#define IMAGE_DEBUG_TYPE_FPO            0x3
#define IMAGE_DEBUG_TYPE_MISC           0x4
#define IMAGE_DEBUG_TYPE_EXCEPTION      0x5
#define IMAGE_DEBUG_TYPE_FIXUP          0x6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC    0x7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  0x8
#define IMAGE_DEBUG_TYPE_BORLAND        0x9
#define IMAGE_DEBUG_TYPE_RESERVED10     0xa
#define IMAGE_DEBUG_TYPE_CLSID          0xb
#define IMAGE_DEBUG_TYPE_VC_FEATURE     0xc
#define IMAGE_DEBUG_TYPE_POGO           0xd
#define IMAGE_DEBUG_TYPE_ILTCG          0xe
#define IMAGE_DEBUG_TYPE_MPX            0xf

typedef struct _DEBUG_DIRECTORY_TABLE
{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    DWORD Type;//DWORD
    DWORD sizeOfData;
    DWORD addressOfRawData;
    DWORD pointerToRawData;
}DEBUG_DIRECTORY_TABLE, * PDEBUG_DIRECTORY_TABLE;

typedef struct _EXCEPTION_DIRECTORY_ENTRY
{
    DWORD beginAddress;
    DWORD endAddress;
    DWORD unwindInformation;  //?UNWIND_INFO
}EXCEPTION_DIRECTORY_ENTRY, * PEXCEPTION_DIRECTORY_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    DWORD EndAddress;
    union
    {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    } __inner2;
}IMAGE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef enum _UNWIND_OP_CODES // int32_t
{
    UWOP_PUSH_NONVOL = 0x0,
    UWOP_ALLOC_LARGE = 0x1,
    UWOP_ALLOC_SMALL = 0x2,
    UWOP_SET_FPREG = 0x3,
    UWOP_SAVE_NONVOL = 0x4,
    UWOP_SAVE_NONVOL_FAR = 0x5,
    UWOP_EPILOG = 0x6,
    UWOP_SPARE_CODE = 0x7,
    UWOP_SAVE_XMM128 = 0x8,
    UWOP_SAVE_XMM128_FAR = 0x9,
    UWOP_PUSH_MACHFRAME = 0xa
}UNWIND_OP_CODES, * PUNWIND_OP_CODES;

typedef struct _UNWIND_INFO
{
    UCHAR VersionAndFlag;
    UCHAR SizeOfProlog;
    UCHAR CountOfUnwindCodes;
    UCHAR FrameRegisterAndFrameRegisterOffset;
}UNWIND_INFO, * PUNWIND_INFO;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY
{
    PVOID ImageBase;
    IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionEntry;
}UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE
{
    DWORD Count;
    UCHAR LocalHint;
    UCHAR GlobalHint;
    UCHAR Search;
    UCHAR Once;
    QWORD LowAddress;
    QWORD HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[0xc];
}UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

typedef struct _DELAY_IMPORT_DIRECTORY
{
    DWORD attributes;
    DWORD name;
    DWORD moduleHandle;
    DWORD delayImportAddressTable;
    DWORD delayImportNameTable;
    DWORD boundDelayImportTable;
    DWORD unloadDelayImportTable;
    DWORD timestamp;
}DELAY_IMPORT_DIRECTORY, * PDELAY_IMPORT_DIRECTORY;

typedef struct GUARD_CONTROL_FLOW_FUNCTION_TABLE
{
    /*    uint32_t rvAddr;
    uint8_t metadata;*/
    DWORD rvAddr;
    UCHAR metadata;
}GUARD_CONTROL_FLOW_FUNCTION_TABLE, * PGUARD_CONTROL_FLOW_FUNCTION_TABLE;

typedef struct _IMAGE_SECURITY_CONTEXT
{
    union
    {
        PVOID PageHashes;
        QWORD Value;
        union
        {
            QWORD SecurityBeingCreated;
            QWORD SecurityMandatory;
            QWORD PageHashPointer;
        } __bitfield0;
    } __inner0;
}IMAGE_SECURITY_CONTEXT, * PIMAGE_SECURITY_CONTEXT;

typedef struct _IMAGE_AUX_SYMBOL_TOKEN_DEF
{
    UCHAR bAuxType;
    UCHAR bReserved;
    //__offset(0x2);
    DWORD SymbolTableIndex;
    UCHAR rgbReserved[0xc];
}IMAGE_AUX_SYMBOL_TOKEN_DEF, * PIMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef union _IMAGE_AUX_SYMBOL
{
    struct
    {
        DWORD TagIndex;
        union
        {
            struct
            {
                WORD Linenumber;
                WORD Size;
            } LnSz;
            DWORD TotalSize;
        } Misc;
        union
        {
            struct
            {
                DWORD PointerToLinenumber;
                DWORD PointerToNextFunction;
            } Function;
            struct
            {
                WORD Dimension[0x4];
            } Array;
        } FcnAry;
        WORD TvIndex;
    } Sym;
    struct
    {
        UCHAR Name[0x12];
    } File;
    struct
    {
        DWORD Length;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD CheckSum;
        SHORT Number;
        UCHAR Selection;
        UCHAR bReserved;
        SHORT HighNumber;
    } Section;
    IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
    struct
    {
        DWORD crc;
        UCHAR rgbReserved[0xe];
    } CRC;
}IMAGE_AUX_SYMBOL, * PIMAGE_AUX_SYMBOL;

typedef union _IMAGE_AUX_SYMBOL_EX
{
    struct
    {
        DWORD WeakDefaultSymIndex;
        DWORD WeakSearchType;
        UCHAR rgbReserved[0xc];
    } Sym;
    struct
    {
        UCHAR Name[0x14];
    } File;
    struct
    {
        DWORD Length;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD CheckSum;
        SHORT Number;
        UCHAR Selection;
        UCHAR bReserved;
        SHORT HighNumber;
        UCHAR rgbReserved[0x2];
    } Section;
    struct
    {
        IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
        UCHAR rgbReserved[0x2];
    } __inner3;
    struct
    {
        DWORD crc;
        UCHAR rgbReserved[0x10];
    } CRC;
}IMAGE_AUX_SYMBOL_EX, * PIMAGE_AUX_SYMBOL_EX;

typedef struct _IMAGE_BOUND_FORWARDER_REF
{
    DWORD TimeDateStamp;
    WORD OffsetModuleName;
    WORD Reserved;
}IMAGE_BOUND_FORWARDER_REF, * PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
{
    DWORD TimeDateStamp;
    WORD OffsetModuleName;
    WORD NumberOfModuleForwarderRefs;
}IMAGE_BOUND_IMPORT_DESCRIPTOR, * PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY
{
    DWORD FuncStart;
    union
    {
        DWORD PrologLen;
        DWORD FuncLen;
        DWORD ThirtyTwoBit;
        DWORD ExceptionFlag;
    } __bitfield4;
}IMAGE_CE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

#define IMAGE_DEBUG_TYPE_UNKNOWN                0
#define IMAGE_DEBUG_TYPE_COFF                   1
#define IMAGE_DEBUG_TYPE_CODEVIEW               2
#define IMAGE_DEBUG_TYPE_FPO                    3
#define IMAGE_DEBUG_TYPE_MISC                   4
#define IMAGE_DEBUG_TYPE_EXCEPTION              5
#define IMAGE_DEBUG_TYPE_FIXUP                  6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC            7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC          8
#define IMAGE_DEBUG_TYPE_BORLAND                9
#define IMAGE_DEBUG_TYPE_RESERVED10             10
#define IMAGE_DEBUG_TYPE_BBT                    IMAGE_DEBUG_TYPE_RESERVED10
#define IMAGE_DEBUG_TYPE_CLSID                  11
#define IMAGE_DEBUG_TYPE_VC_FEATURE             12
#define IMAGE_DEBUG_TYPE_POGO                   13
#define IMAGE_DEBUG_TYPE_ILTCG                  14
#define IMAGE_DEBUG_TYPE_MPX                    15
#define IMAGE_DEBUG_TYPE_REPRO                  16
#define IMAGE_DEBUG_TYPE_SPGO                   18
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS  20

typedef struct _IMAGE_DEBUG_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Type;
    DWORD SizeOfData;
    DWORD AddressOfRawData;
    DWORD PointerToRawData;
}IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC
{
    DWORD DataType;
    DWORD Length;
    UCHAR Unicode;
    UCHAR Reserved[0x3];
    UCHAR Data[0x1];
}IMAGE_DEBUG_MISC, * PIMAGE_DEBUG_MISC;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR
{
    union
    {
        DWORD AllAttributes;
        DWORD RvaBased;
        DWORD ReservedAttributes;
    } Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
}IMAGE_DELAYLOAD_DESCRIPTOR, * PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_DYNAMIC_RELOCATION32
{
    DWORD Symbol;
    DWORD BaseRelocSize;
}IMAGE_DYNAMIC_RELOCATION32, * PIMAGE_DYNAMIC_RELOCATION32;

typedef struct _IMAGE_DYNAMIC_RELOCATION32_V2
{
    DWORD HeaderSize;
    DWORD FixupInfoSize;
    DWORD Symbol;
    DWORD SymbolGroup;
    DWORD Flags;
}IMAGE_DYNAMIC_RELOCATION32_V2, * PIMAGE_DYNAMIC_RELOCATION32_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION64
{
    QWORD Symbol;
    DWORD BaseRelocSize;
}IMAGE_DYNAMIC_RELOCATION64, * PIMAGE_DYNAMIC_RELOCATION64;

typedef struct _IMAGE_DYNAMIC_RELOCATION64_V2
{
    DWORD HeaderSize;
    DWORD FixupInfoSize;
    QWORD Symbol;
    DWORD SymbolGroup;
    DWORD Flags;
}IMAGE_DYNAMIC_RELOCATION64_V2, * PIMAGE_DYNAMIC_RELOCATION64_V2;

typedef struct _IMAGE_DYNAMIC_RELOCATION_TABLE
{
    DWORD Version;
    DWORD Size;
}IMAGE_DYNAMIC_RELOCATION_TABLE, * PIMAGE_DYNAMIC_RELOCATION_TABLE;

typedef struct _IMAGE_ENCLAVE_CONFIG32
{
    DWORD Size;
    DWORD MinimumRequiredConfigSize;
    DWORD PolicyFlags;
    DWORD NumberOfImports;
    DWORD ImportList;
    DWORD ImportEntrySize;
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImageVersion;
    DWORD SecurityVersion;
    DWORD EnclaveSize;
    DWORD NumberOfThreads;
    DWORD EnclaveFlags;
}IMAGE_ENCLAVE_CONFIG32, * PIMAGE_ENCLAVE_CONFIG32;

typedef struct _IMAGE_ENCLAVE_CONFIG64
{
    DWORD Size;
    DWORD MinimumRequiredConfigSize;
    DWORD PolicyFlags;
    DWORD NumberOfImports;
    DWORD ImportList;
    DWORD ImportEntrySize;
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImageVersion;
    DWORD SecurityVersion;
    QWORD EnclaveSize;
    DWORD NumberOfThreads;
    DWORD EnclaveFlags;
}IMAGE_ENCLAVE_CONFIG64, * PIMAGE_ENCLAVE_CONFIG64;

#define IMAGE_ENCLAVE_POLICY_DEBUGGABLE     0x00000001
#define IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE    0x00000001

#define IMAGE_ENCLAVE_IMPORT_MATCH_NONE             0x00000000
#define IMAGE_ENCLAVE_IMPORT_MATCH_UNIQUE_ID        0x00000001
#define IMAGE_ENCLAVE_IMPORT_MATCH_AUTHOR_ID        0x00000002
#define IMAGE_ENCLAVE_IMPORT_MATCH_FAMILY_ID        0x00000003
#define IMAGE_ENCLAVE_IMPORT_MATCH_IMAGE_ID         0x00000004

typedef struct _IMAGE_ENCLAVE_IMPORT
{
    DWORD MatchType;
    DWORD MinimumSecurityVersion;
    UCHAR UniqueOrAuthorID[0x20];
    UCHAR FamilyID[0x10];
    UCHAR ImageID[0x10];
    DWORD ImportName;
    DWORD Reserved;
}IMAGE_ENCLAVE_IMPORT, * PIMAGE_ENCLAVE_IMPORT;

typedef struct _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER
{
    DWORD EpilogueCount;
    UCHAR EpilogueByteCount;
    UCHAR BranchDescriptorElementSize;
    WORD BranchDescriptorCount;
}IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER, * PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_FUNCTION_ENTRY
{
    DWORD StartingAddress;
    DWORD EndingAddress;
    DWORD EndOfPrologue;
}IMAGE_FUNCTION_ENTRY, * PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64
{
    QWORD StartingAddress;
    QWORD EndingAddress;
    union
    {
        QWORD EndOfPrologue;
        QWORD UnwindInfoAddress;
    } __inner2;
}IMAGE_FUNCTION_ENTRY64, * PIMAGE_FUNCTION_ENTRY64;

typedef struct _IMAGE_HOT_PATCH_BASE
{
    DWORD SequenceNumber;
    DWORD Flags;
    DWORD OriginalTimeDateStamp;
    DWORD OriginalCheckSum;
    DWORD CodeIntegrityInfo;
    DWORD CodeIntegritySize;
    DWORD PatchTable;
    DWORD BufferOffset;
}IMAGE_HOT_PATCH_BASE, * PIMAGE_HOT_PATCH_BASE;

typedef struct _IMAGE_HOT_PATCH_HASHES
{
    UCHAR SHA256[0x20];
    UCHAR SHA1[0x14];
}IMAGE_HOT_PATCH_HASHES, * PIMAGE_HOT_PATCH_HASHES;

typedef struct _IMAGE_HOT_PATCH_INFO
{
    DWORD Version;
    DWORD Size;
    DWORD SequenceNumber;
    DWORD BaseImageList;
    DWORD BaseImageCount;
    DWORD BufferOffset;
    DWORD ExtraPatchSize;
}IMAGE_HOT_PATCH_INFO, * PIMAGE_HOT_PATCH_INFO;

typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION
{
    union
    {
        DWORD PageRelativeOffset;
        DWORD IndirectCall;
        DWORD IATIndex;
    } __bitfield0;
}IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION, * PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

typedef struct _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION
{
    union
    {
        WORD PageRelativeOffset;
        WORD IndirectCall;
        WORD RexWPrefix;
        WORD CfgCheck;
        DWORD Reserved;
    } __bitfield0;
}IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION, * PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION;

typedef struct _IMAGE_LINENUMBER
{
    union
    {
        DWORD SymbolTableIndex;
        DWORD VirtualAddress;
    } Type;
    WORD Linenumber;
}IMAGE_LINENUMBER, * PIMAGE_LINENUMBER;

#define IMAGE_HOT_PATCH_BASE_OBLIGATORY     0x00000001
#define IMAGE_HOT_PATCH_BASE_CAN_ROLL_BACK  0x00000002

#define IMAGE_HOT_PATCH_CHUNK_INVERSE       0x80000000
#define IMAGE_HOT_PATCH_CHUNK_OBLIGATORY    0x40000000
#define IMAGE_HOT_PATCH_CHUNK_RESERVED      0x3FF03000
#define IMAGE_HOT_PATCH_CHUNK_TYPE          0x000FC000
#define IMAGE_HOT_PATCH_CHUNK_SOURCE_RVA    0x00008000
#define IMAGE_HOT_PATCH_CHUNK_TARGET_RVA    0x00004000
#define IMAGE_HOT_PATCH_CHUNK_SIZE          0x00000FFF

#define IMAGE_HOT_PATCH_NONE                0x00000000
#define IMAGE_HOT_PATCH_FUNCTION            0x0001C000
#define IMAGE_HOT_PATCH_ABSOLUTE            0x0002C000
#define IMAGE_HOT_PATCH_REL32               0x0003C000
#define IMAGE_HOT_PATCH_CALL_TARGET         0x00044000
#define IMAGE_HOT_PATCH_INDIRECT            0x0005C000
#define IMAGE_HOT_PATCH_NO_CALL_TARGET      0x00064000
#define IMAGE_HOT_PATCH_DYNAMIC_VALUE       0x00078000

#define IMAGE_GUARD_CF_INSTRUMENTED                    0x00000100 // Module performs control flow integrity checks using system-supplied support
#define IMAGE_GUARD_CFW_INSTRUMENTED                   0x00000200 // Module performs control flow and write integrity checks
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          0x00000400 // Module contains valid control flow target metadata
#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED             0x00000800 // Module does not make use of the /GS security cookie
#define IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              0x00001000 // Module supports read only delay load IAT
#define IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   0x00002000 // Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000 // Module contains suppressed export information. This also infers that the address taken
// taken IAT table is also present in the load config.
#define IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       0x00008000 // Module enables suppression of exports
#define IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          0x00010000 // Module contains longjmp target information
#define IMAGE_GUARD_RF_INSTRUMENTED                    0x00020000 // Module contains return flow instrumentation and metadata
#define IMAGE_GUARD_RF_ENABLE                          0x00040000 // Module requests that the OS enable return flow protection
#define IMAGE_GUARD_RF_STRICT                          0x00080000 // Module requests that the OS enable return flow protection in strict mode
#define IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000 // Module was built with retpoline support
// DO_NOT_USE                                          0x00200000 // Was EHCont flag on VB (20H1)
#define IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT      0x00400000 // Module contains EH continuation target information
#define IMAGE_GUARD_XFG_ENABLED                        0x00800000 // Module was built with xfg
#define IMAGE_GUARD_CASTGUARD_PRESENT                  0x01000000 // Module has CastGuard instrumentation present
#define IMAGE_GUARD_MEMCPY_PRESENT                     0x02000000 // Module has Guarded Memcpy instrumentation present

#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        0xF0000000 // Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       28         // Shift to right-justify Guard CF function table stride

//
// GFIDS table entry flags.
//

#define IMAGE_GUARD_FLAG_FID_SUPPRESSED               0x01       // The containing GFID entry is suppressed
#define IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED            0x02       // The containing GFID entry is export suppressed
#define IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER         0x04
#define IMAGE_GUARD_FLAG_FID_XFG                      0x08

typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY
{
    WORD Flags;
    WORD Catalog;
    DWORD CatalogOffset;
    DWORD Reserved;
}IMAGE_LOAD_CONFIG_CODE_INTEGRITY, * PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32
{
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    DWORD DeCommitFreeBlockThreshold;
    DWORD DeCommitTotalFreeThreshold;
    DWORD LockPrefixTable;
    DWORD MaximumAllocationSize;
    DWORD VirtualMemoryThreshold;
    DWORD ProcessHeapFlags;
    DWORD ProcessAffinityMask;
    WORD CSDVersion;
    WORD DependentLoadFlags;
    DWORD EditList;
    DWORD SecurityCookie;
    DWORD SEHandlerTable;
    DWORD SEHandlerCount;
    DWORD GuardCFCheckFunctionPointer;
    DWORD GuardCFDispatchFunctionPointer;
    DWORD GuardCFFunctionTable;
    DWORD GuardCFFunctionCount;
    DWORD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    DWORD GuardAddressTakenIatEntryTable;
    DWORD GuardAddressTakenIatEntryCount;
    DWORD GuardLongJumpTargetTable;
    DWORD GuardLongJumpTargetCount;
    DWORD DynamicValueRelocTable;
    DWORD CHPEMetadataPointer;
    DWORD GuardRFFailureRoutine;
    DWORD GuardRFFailureRoutineFunctionPointer;
    DWORD DynamicValueRelocTableOffset;
    WORD DynamicValueRelocTableSection;
    WORD Reserved2;
    DWORD GuardRFVerifyStackPointerFunctionPointer;
    DWORD HotPatchTableOffset;
    DWORD Reserved3;
    DWORD EnclaveConfigurationPointer;
    DWORD VolatileMetadataPointer;
    DWORD GuardEHContinuationTable;
    DWORD GuardEHContinuationCount;
}IMAGE_LOAD_CONFIG_DIRECTORY32, * PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64
{
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    QWORD DeCommitFreeBlockThreshold;
    QWORD DeCommitTotalFreeThreshold;
    QWORD LockPrefixTable;
    QWORD MaximumAllocationSize;
    QWORD VirtualMemoryThreshold;
    QWORD ProcessAffinityMask;
    DWORD ProcessHeapFlags;
    WORD CSDVersion;
    WORD DependentLoadFlags;
    QWORD EditList;
    QWORD SecurityCookie;
    QWORD SEHandlerTable;
    QWORD SEHandlerCount;
    QWORD GuardCFCheckFunctionPointer;
    QWORD GuardCFDispatchFunctionPointer;
    QWORD GuardCFFunctionTable;
    QWORD GuardCFFunctionCount;
    DWORD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    QWORD GuardAddressTakenIatEntryTable;
    QWORD GuardAddressTakenIatEntryCount;
    QWORD GuardLongJumpTargetTable;
    QWORD GuardLongJumpTargetCount;
    QWORD DynamicValueRelocTable;
    QWORD CHPEMetadataPointer;
    QWORD GuardRFFailureRoutine;
    QWORD GuardRFFailureRoutineFunctionPointer;
    DWORD DynamicValueRelocTableOffset;
    WORD DynamicValueRelocTableSection;
    WORD Reserved2;
    QWORD GuardRFVerifyStackPointerFunctionPointer;
    DWORD HotPatchTableOffset;
    DWORD Reserved3;
    QWORD EnclaveConfigurationPointer;
    QWORD VolatileMetadataPointer;
    QWORD GuardEHContinuationTable;
    QWORD GuardEHContinuationCount;
}IMAGE_LOAD_CONFIG_DIRECTORY64, * PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum _IMAGE_MITIGATION_POLICY// int32_t
{
    ImageDepPolicy = 0x0,
    ImageAslrPolicy = 0x1,
    ImageDynamicCodePolicy = 0x2,
    ImageStrictHandleCheckPolicy = 0x3,
    ImageSystemCallDisablePolicy = 0x4,
    ImageMitigationOptionsMask = 0x5,
    ImageExtensionPointDisablePolicy = 0x6,
    ImageControlFlowGuardPolicy = 0x7,
    ImageSignaturePolicy = 0x8,
    ImageFontDisablePolicy = 0x9,
    ImageImageLoadPolicy = 0xa,
    ImagePayloadRestrictionPolicy = 0xb,
    ImageChildProcessPolicy = 0xc,
    ImageSehopPolicy = 0xd,
    ImageHeapPolicy = 0xe,
    ImageUserShadowStackPolicy = 0xf,
    MaxImageMitigationPolicy = 0x10
}IMAGE_MITIGATION_POLICY, * PIMAGE_MITIGATION_POLICY;

typedef enum _IMAGE_POLICY_ENTRY_TYPE // int32_t
{
    ImagePolicyEntryTypeNone = 0x0,
    ImagePolicyEntryTypeBool = 0x1,
    ImagePolicyEntryTypeInt8 = 0x2,
    ImagePolicyEntryTypeUInt8 = 0x3,
    ImagePolicyEntryTypeInt16 = 0x4,
    ImagePolicyEntryTypeUInt16 = 0x5,
    ImagePolicyEntryTypeInt32 = 0x6,
    ImagePolicyEntryTypeUInt32 = 0x7,
    ImagePolicyEntryTypeInt64 = 0x8,
    ImagePolicyEntryTypeUInt64 = 0x9,
    ImagePolicyEntryTypeAnsiString = 0xa,
    ImagePolicyEntryTypeUnicodeString = 0xb,
    ImagePolicyEntryTypeOverride = 0xc,
    ImagePolicyEntryTypeMaximum = 0xd
}IMAGE_POLICY_ENTRY_TYPE, * PIMAGE_POLICY_ENTRY_TYPE;

typedef enum _IMAGE_POLICY_ID // int32_t
{
    ImagePolicyIdNone = 0x0,
    ImagePolicyIdEtw = 0x1,
    ImagePolicyIdDebug = 0x2,
    ImagePolicyIdCrashDump = 0x3,
    ImagePolicyIdCrashDumpKey = 0x4,
    ImagePolicyIdCrashDumpKeyGuid = 0x5,
    ImagePolicyIdParentSd = 0x6,
    ImagePolicyIdParentSdRev = 0x7,
    ImagePolicyIdSvn = 0x8,
    ImagePolicyIdDeviceId = 0x9,
    ImagePolicyIdCapability = 0xa,
    ImagePolicyIdScenarioId = 0xb,
    ImagePolicyIdMaximum = 0xc
}IMAGE_POLICY_ID, * PIMAGE_POLICY_ID;

typedef struct _IMAGE_POLICY_ENTRY
{
    IMAGE_POLICY_ENTRY_TYPE Type;
    IMAGE_POLICY_ID PolicyId;
    union
    {
        void const* None;
        UCHAR BoolValue;
        char Int8Value;
        UCHAR UInt8Value;
        SHORT Int16Value;
        WORD UInt16Value;
        LONG Int32Value;
        DWORD UInt32Value;
        __int64 Int64Value;
        QWORD UInt64Value;
        char const* AnsiStringValue;
        PWSTR const* UnicodeStringValue;
    } u;
}IMAGE_POLICY_ENTRY, * PIMAGE_POLICY_ENTRY;

typedef struct _IMAGE_POLICY_METADATA
{
    UCHAR Version;
    UCHAR Reserved0[0x7];
    QWORD ApplicationId;
    struct _IMAGE_POLICY_ENTRY Policies[0x0];
}IMAGE_POLICY_METADATA, * PIMAGE_POLICY_METADATA;

typedef struct _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER
{
    UCHAR PrologueByteCount;
}IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER, * PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER;

typedef struct _IMAGE_RELOCATION
{
    union
    {
        DWORD VirtualAddress;
        DWORD RelocCount;
    } __inner0;
    DWORD SymbolTableIndex;
    WORD Type;
}IMAGE_RELOCATION, * PIMAGE_RELOCATION;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
}IMAGE_RESOURCE_DATA_ENTRY, * PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    WORD NumberOfNamedEntries;
    WORD NumberOfIdEntries;
}IMAGE_RESOURCE_DIRECTORY, * PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        } DUMMYSTRUCTNAME;
        DWORD   Name;
        WORD    Id;
    } DUMMYUNIONNAME;
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory : 31;
            DWORD   DataIsDirectory : 1;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, * PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING
{
    WORD Length;
    char NameString[0x1];
}IMAGE_RESOURCE_DIRECTORY_STRING, * PIMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U
{
    WORD Length;
    UCHAR NameString[0x1];
}IMAGE_RESOURCE_DIR_STRING_U, * PIMAGE_RESOURCE_DIR_STRING_U;

typedef struct _NON_PAGED_DEBUG_INFO {
    WORD        Signature;
    WORD        Flags;
    DWORD       Size;
    WORD        Machine;
    WORD        Characteristics;
    DWORD       TimeDateStamp;
    DWORD       CheckSum;
    DWORD       SizeOfImage;
    ULONGLONG   ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the old checksum didn't match.

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER
{
    WORD Signature;
    WORD Flags;
    WORD Machine;
    WORD Characteristics;
    DWORD TimeDateStamp;
    DWORD CheckSum;
    DWORD ImageBase;
    DWORD SizeOfImage;
    DWORD NumberOfSections;
    DWORD ExportedNamesSize;
    DWORD DebugDirectorySize;
    DWORD SectionAlignment;
    DWORD Reserved[0x2];
}IMAGE_SEPARATE_DEBUG_HEADER, * PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION
{
    union
    {
        WORD PageRelativeOffset;
        WORD RegisterNumber;
    } __bitfield0;
}IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION, * PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION;

#define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.
#define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special
#define IMAGE_SYM_SECTION_MAX_EX      MAXLONG

#define IMAGE_SYM_TYPE_NULL                 0x0000  // no type.
#define IMAGE_SYM_TYPE_VOID                 0x0001  //
#define IMAGE_SYM_TYPE_CHAR                 0x0002  // type character.
#define IMAGE_SYM_TYPE_SHORT                0x0003  // type short integer.
#define IMAGE_SYM_TYPE_INT                  0x0004  //
#define IMAGE_SYM_TYPE_LONG                 0x0005  //
#define IMAGE_SYM_TYPE_FLOAT                0x0006  //
#define IMAGE_SYM_TYPE_DOUBLE               0x0007  //
#define IMAGE_SYM_TYPE_STRUCT               0x0008  //
#define IMAGE_SYM_TYPE_UNION                0x0009  //
#define IMAGE_SYM_TYPE_ENUM                 0x000A  // enumeration.
#define IMAGE_SYM_TYPE_MOE                  0x000B  // member of enumeration.
#define IMAGE_SYM_TYPE_BYTE                 0x000C  //
#define IMAGE_SYM_TYPE_WORD                 0x000D  //
#define IMAGE_SYM_TYPE_UINT                 0x000E  //
#define IMAGE_SYM_TYPE_DWORD                0x000F  //
#define IMAGE_SYM_TYPE_PCODE                0x8000  //

#define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
#define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
#define IMAGE_SYM_DTYPE_ARRAY               3       // array.

#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044  //

#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
// new
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

#define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2
// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) & N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif


typedef struct _IMAGE_SYMBOL
{
    union
    {
        UCHAR ShortName[0x8];
        struct
        {
            DWORD Short;
            DWORD Long;
        } Name;
        DWORD LongName[0x2];
    } N;
    DWORD Value;
    SHORT SectionNumber;
    WORD Type;
    UCHAR StorageClass;
    UCHAR NumberOfAuxSymbols;
}IMAGE_SYMBOL, * PIMAGE_SYMBOL;

typedef struct _IMAGE_SYMBOL_EX
{
    union
    {
        UCHAR ShortName[0x8];
        struct
        {
            DWORD Short;
            DWORD Long;
        } Name;
        DWORD LongName[0x2];
    } N;
    DWORD Value;
    LONG SectionNumber;
    WORD Type;
    UCHAR StorageClass;
    UCHAR NumberOfAuxSymbols;
}IMAGE_SYMBOL_EX, * PIMAGE_SYMBOL_EX;

typedef enum _FUNCTION_TABLE_TYPE //int32_t
{
    RF_SORTED = 0x0,
    RF_UNSORTED = 0x1,
    RF_CALLBACK = 0x2,
    RF_KERNEL_DYNAMIC = 0x3
}FUNCTION_TABLE_TYPE, * PFUNCTION_TABLE_TYPE;

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x4
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x8
            UCHAR Balance : 2;                                                //0x8
        };
        ULONG ParentValue;                                                  //0x8
    };
}RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _DYNAMIC_FUNCTION_TABLE
{
    LIST_ENTRY ListEntry;
    IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
    LARGE_INTEGER TimeStamp;
    QWORD MinimumAddress;
    QWORD MaximumAddress;
    QWORD BaseAddress;
    IMAGE_RUNTIME_FUNCTION_ENTRY* (*Callback)(QWORD, PVOID);
    PVOID Context;
    USHORT* OutOfProcessCallbackDll;
    FUNCTION_TABLE_TYPE Type;
    DWORD EntryCount;
    RTL_BALANCED_NODE TreeNodeMin;
    RTL_BALANCED_NODE TreeNodeMax;
}DYNAMIC_FUNCTION_TABLE, * PDYNAMIC_FUNCTION_TABLE;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    union
    {
        IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
        DYNAMIC_FUNCTION_TABLE* DynamicTable;
    } __inner0;
    PVOID ImageBase;
    DWORD SizeOfImage;
    DWORD SizeOfTable;
}INVERTED_FUNCTION_TABLE_ENTRY, * PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE
{
    DWORD CurrentSize;
    DWORD MaximumSize;
    DWORD volatile Epoch;
    UCHAR Overflow;
    INVERTED_FUNCTION_TABLE_ENTRY TableEntry[0x200];
}INVERTED_FUNCTION_TABLE, * PINVERTED_FUNCTION_TABLE;

typedef struct _IMAGE_ARCHITECTURE_ENTRY
{
    DWORD FixupInstRVA;
    DWORD NewInst;
}IMAGE_ARCHITECTURE_ENTRY, * PIMAGE_ARCHITECTURE_ENTRY;

/*typedef struct _IMAGE_ARCHITECTURE_HEADER {
    unsigned int AmaskValue : 1;                 // 1 -> code section depends on mask bit
    // 0 -> new instruction depends on mask bit
    int : 7;                                     // MBZ
    unsigned int AmaskShift : 8;                 // Amask bit in question for this fixup
    int : 16;                                    // MBZ
    DWORD FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;*/
/*
typedef struct _IMAGE_ARCHITECTURE_HEADER
{
    union
    {
        DWORD AmaskValue;
        DWORD AmaskShift;
    } __bitfield0;
    DWORD FirstEntryRVA;
}IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;*/

typedef struct _IMAGE_ARCHITECTURE_HEADER {
    unsigned int AmaskValue : 1;                 // 1 -> code section depends on mask bit
    // 0 -> new instruction depends on mask bit
    int : 7;                                     // MBZ
    unsigned int AmaskShift : 8;                 // Amask bit in question for this fixup
    int : 16;                                    // MBZ
    DWORD FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, * PIMAGE_ARCHITECTURE_HEADER;

typedef struct _OSINFO
{
    DWORD dwOSPlatformId;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
}OSINFO, * POSINFO;

typedef struct _ASSEMBLYMETADATA
{
    USHORT usMajorVersion;
    USHORT usMinorVersion;
    USHORT usBuildNumber;
    USHORT usRevisionNumber;
    USHORT* szLocale;
    DWORD cbLocale;
    DWORD* rProcessor;
    DWORD ulProcessor;
    OSINFO* rOS;
    DWORD ulOS;
}ASSEMBLYMETADATA, * PASSEMBLYMETADATA;

typedef struct _JIT_DEBUG_INFO
{
    DWORD dwSize;
    DWORD dwProcessorArchitecture;
    DWORD dwThreadID;
    DWORD dwReserved0;
    QWORD lpExceptionAddress;
    QWORD lpExceptionRecord;
    QWORD lpContextRecord;
}JIT_DEBUG_INFO, * PJIT_DEBUG_INFO;

//FROM LDR 
typedef struct _LOADED_IMAGE
{
    char* ModuleName;
    PVOID hFile;
    UCHAR* MappedAddress;
    IMAGE_NT_HEADERS64* FileHeader;
    IMAGE_SECTION_HEADER* LastRvaSection;
    DWORD NumberOfSections;
    IMAGE_SECTION_HEADER* Sections;
    DWORD Characteristics;
    UCHAR fSystemImage;
    UCHAR fDOSImage;
    UCHAR fReadOnly;
    UCHAR Version;
    LIST_ENTRY Links;
    DWORD SizeOfImage;
}LOADED_IMAGE, * PLOADED_IMAGE;

typedef struct _LOAD_ASDATA_TABLE
{
    PVOID Module;
    PWSTR FilePath;
    QWORD Size;
    PVOID* Handle;
    LONG RefCount;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
}LOAD_ASDATA_TABLE, * PLOAD_ASDATA_TABLE;

typedef struct _LOAD_DLL_DEBUG_INFO
{
    PVOID hFile;
    PVOID lpBaseOfDll;
    DWORD dwDebugInfoFileOffset;
    DWORD nDebugInfoSize;
    PVOID lpImageName;
    WORD fUnicode;
}LOAD_DLL_DEBUG_INFO, * PLOAD_DLL_DEBUG_INFO;

typedef struct _LOCALMANAGEDAPPLICATION
{
    PWSTR pszDeploymentName;
    PWSTR pszPolicyName;
    PWSTR pszProductId;
    DWORD dwState;
}LOCALMANAGEDAPPLICATION, * PLOCALMANAGEDAPPLICATION;

typedef struct _HOT_PATCH_IMAGE_INFO
{
    DWORD CheckSum;
    DWORD TimeDateStamp;
}HOT_PATCH_IMAGE_INFO, * PHOT_PATCH_IMAGE_INFO;

typedef struct _MANAGEDAPPLICATION
{
    PWSTR pszPackageName;
    PWSTR pszPublisher;
    DWORD dwVersionHi;
    DWORD dwVersionLo;
    DWORD dwRevision;
    GUID GpoId;
    PWSTR pszPolicyName;
    GUID ProductId;
    USHORT Language;
    PWSTR pszOwner;
    PWSTR pszCompany;
    PWSTR pszComments;
    PWSTR pszContact;
    PWSTR pszSupportUrl;
    DWORD dwPathType;
    LONG bInstalled;
}MANAGEDAPPLICATION, * PMANAGEDAPPLICATION;

typedef struct _SID_IDENTIFIER_AUTHORITY
{
    UCHAR Value[0x6];
}SID_IDENTIFIER_AUTHORITY, * PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID
{
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[0x1];
}SID, * PSID;

typedef struct _MANAGE_HOT_PATCH_LOAD_PATCH
{
    DWORD Version;
    UNICODE_STRING PatchPath;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
    HOT_PATCH_IMAGE_INFO BaseInfo;
}MANAGE_HOT_PATCH_LOAD_PATCH, * PMANAGE_HOT_PATCH_LOAD_PATCH;

typedef struct _MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
{
    DWORD Version;
    PVOID ProcessHandle;
    DWORD PatchCount;
    UNICODE_STRING* PatchPathStrings;
    HOT_PATCH_IMAGE_INFO* BaseInfos;
}MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES, * PMANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES;

typedef struct _MANAGE_HOT_PATCH_QUERY_PATCHES
{
    DWORD Version;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
    DWORD PatchCount;
    UNICODE_STRING* PatchPathStrings;
    HOT_PATCH_IMAGE_INFO* BaseInfos;
}MANAGE_HOT_PATCH_QUERY_PATCHES, * PMANAGE_HOT_PATCH_QUERY_PATCHES;

typedef struct _MANAGE_HOT_PATCH_UNLOAD_PATCH
{
    DWORD Version;
    HOT_PATCH_IMAGE_INFO BaseInfo;
    union
    {
        SID Sid;
        UCHAR Buffer[0x44];
    } UserSid;
}MANAGE_HOT_PATCH_UNLOAD_PATCH, * PMANAGE_HOT_PATCH_UNLOAD_PATCH;

typedef struct _MANAGE_WRITES_TO_EXECUTABLE_MEMORY
{
    union
    {
        DWORD Version;
        DWORD ProcessEnableWriteExceptions;
        DWORD ThreadAllowWrites;
        DWORD Spare;
    } __bitfield0;
    PVOID KernelWriteToExecutableSignal;
}MANAGE_WRITES_TO_EXECUTABLE_MEMORY, * PMANAGE_WRITES_TO_EXECUTABLE_MEMORY;

//-----------------------------------------------------------------------------------

#define MEM_COMMIT                                             0x00001000  
#define MEM_PRIVATE                                            0x00020000
#define MEM_RESERVE                                            0x00002000  
#define MEM_REPLACE_PLACEHOLDER                                0x00004000  
#define MEM_MAPPED                                             0x00040000 
#define MEM_IMAGE                                              0x1000000
#define MEM_RESET                                              0x00080000  
#define MEM_TOP_DOWN                                           0x00100000  
#define MEM_WRITE_WATCH                                        0x00200000  
#define MEM_PHYSICAL                                           0x00400000  
#define MEM_ROTATE                                             0x00800000  
#define MEM_DIFFERENT_IMAGE_BASE_OK                            0x00800000  
#define MEM_RESET_UNDO                                         0x01000000  
#define MEM_LARGE_PAGES                                        0x20000000  
#define MEM_4MB_PAGES                                          0x80000000  
#define MEM_64K_PAGES                                          (MEM_LARGE_PAGES | MEM_PHYSICAL)  
#define MEM_UNMAP_WITH_TRANSIENT_BOOST                         0x00000001  
#define MEM_COALESCE_PLACEHOLDERS                              0x00000001  
#define MEM_PRESERVE_PLACEHOLDER                               0x00000002 
#define MEM_FREE                                               0x00010000  

#define PAGE_NOACCESS                                          0x01    
#define PAGE_READONLY                                          0x02    
#define PAGE_READWRITE                                         0x04    
#define PAGE_WRITECOPY                                         0x08    
#define PAGE_EXECUTE                                           0x10    
#define PAGE_EXECUTE_READ                                      0x20    
#define PAGE_EXECUTE_READWRITE                                 0x40    
#define PAGE_EXECUTE_WRITECOPY                                 0x80    
#define PAGE_GUARD                                             0x100    
#define PAGE_NOCACHE                                           0x200    
#define PAGE_WRITECOMBINE                                      0x400    
#define PAGE_GRAPHICS_NOACCESS                                 0x0800    
#define PAGE_GRAPHICS_READONLY                                 0x1000    
#define PAGE_GRAPHICS_READWRITE                                0x2000    
#define PAGE_GRAPHICS_EXECUTE                                  0x4000    
#define PAGE_GRAPHICS_EXECUTE_READ                             0x8000    
#define PAGE_GRAPHICS_EXECUTE_READWRITE                        0x10000    
#define PAGE_GRAPHICS_COHERENT                                 0x20000    
#define PAGE_GRAPHICS_NOCACHE                                  0x40000    
#define PAGE_ENCLAVE_THREAD_CONTROL                            0x80000000  
#define PAGE_REVERT_TO_FILE_MAP                                0x80000000  
#define PAGE_TARGETS_NO_UPDATE                                 0x40000000  
#define PAGE_TARGETS_INVALID                                   0x40000000  
#define PAGE_ENCLAVE_UNVALIDATED                               0x20000000  
#define PAGE_ENCLAVE_MASK                                      0x10000000  
#define PAGE_ENCLAVE_DECOMMIT                                  (PAGE_ENCLAVE_MASK | 0) 
#define PAGE_ENCLAVE_SS_FIRST                                  (PAGE_ENCLAVE_MASK | 1) 
#define PAGE_ENCLAVE_SS_REST                                   (PAGE_ENCLAVE_MASK | 2) 

#define MEM_DECOMMIT                                           0x00004000  
#define MEM_RELEASE                                            0x00008000  

#define OBJ_INHERIT                             0x00000002
#define OBJ_PERMANENT                           0x00000010
#define	OBJ_EXCLUSIVE                           0x00000020
#define	OBJ_CASE_INSENSITIVE                    0x00000040
#define	OBJ_OPENIF                              0x00000080
#define	OBJ_OPENLINK                            0x00000100
#define	OBJ_KERNEL_HANDLE                       0x00000200
#define	OBJ_FORCE_ACCESS_CHECK                  0x00000400
#define	OBJ_VALID_ATTRIBUTES                    0x000007f2

#define DELETE                                  0x00010000L
#define READ_CONTROL                            0x00020000L
#define WRITE_DAC                               0x00040000L
#define WRITE_OWNER                             0x00080000L
#define SYNCHRONIZE                             0x00100000L
#define STANDARD_RIGHTS_REQUIRED                0x000F0000L
#define STANDARD_RIGHTS_READ                    READ_CONTROL
#define STANDARD_RIGHTS_WRITE                   READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE                 READ_CONTROL
#define STANDARD_RIGHTS_ALL                     0x001F0000L
#define SPECIFIC_RIGHTS_ALL                     0x0000FFFFL
#define ACCESS_SYSTEM_SECURITY                  0x01000000L
#define MAXIMUM_ALLOWED                         0x02000000L
#define GENERIC_READ                            0x80000000L
#define GENERIC_WRITE                           0x40000000L
#define GENERIC_EXECUTE                         0x20000000L
#define GENERIC_ALL                             0x10000000L

#define 	FILE_DIRECTORY_FILE                 0x00000001
#define 	FILE_WRITE_THROUGH                  0x00000002
#define 	FILE_SEQUENTIAL_ONLY                0x00000004
#define 	FILE_NO_INTERMEDIATE_BUFFERING      0x00000008
#define 	FILE_SYNCHRONOUS_IO_ALERT           0x00000010
#define 	FILE_SYNCHRONOUS_IO_NONALERT        0x00000020
#define 	FILE_NON_DIRECTORY_FILE             0x00000040
#define 	FILE_CREATE_TREE_CONNECTION         0x00000080
#define 	FILE_COMPLETE_IF_OPLOCKED           0x00000100
#define 	FILE_NO_EA_KNOWLEDGE                0x00000200
#define 	FILE_OPEN_FOR_RECOVERY              0x00000400
#define 	FILE_RANDOM_ACCESS                  0x00000800
#define 	FILE_DELETE_ON_CLOSE                0x00001000
#define 	FILE_OPEN_BY_FILE_ID                0x00002000
#define 	FILE_OPEN_FOR_BACKUP_INTENT         0x00004000
#define 	FILE_NO_COMPRESSION                 0x00008000
#define 	FILE_OPEN_REQUIRING_OPLOCK          0x00010000
#define 	FILE_DISALLOW_EXCLUSIVE             0x00020000
#define 	FILE_SESSION_AWARE                  0x00040000
#define 	FILE_RESERVE_OPFILTER               0x00100000
#define 	FILE_OPEN_REPARSE_POINT             0x00200000
#define 	FILE_OPEN_NO_RECALL                 0x00400000
#define 	FILE_OPEN_FOR_FREE_SPACE_QUERY      0x00800000
#define 	FILE_COPY_STRUCTURED_STORAGE        0x00000041
#define 	FILE_STRUCTURED_STORAGE             0x00000441
#define 	FILE_SUPERSEDED                     0x00000000
#define 	FILE_OPENED                         0x00000001
#define 	FILE_CREATED                        0x00000002
#define 	FILE_OVERWRITTEN                    0x00000003
#define 	FILE_EXISTS                         0x00000004
#define 	FILE_DOES_NOT_EXIST                 0x00000005
#define 	FILE_WRITE_TO_END_OF_FILE           0xffffffff
#define 	FILE_USE_FILE_POINTER_POSITION      0xfffffffe

#define FILE_SHARE_READ                         0x00000001  
#define FILE_SHARE_WRITE                        0x00000002  
#define FILE_SHARE_DELETE                       0x00000004  
#define FILE_ATTRIBUTE_READONLY                 0x00000001  
#define FILE_ATTRIBUTE_HIDDEN                   0x00000002  
#define FILE_ATTRIBUTE_SYSTEM                   0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY                0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE                  0x00000020  
#define FILE_ATTRIBUTE_DEVICE                   0x00000040  
#define FILE_ATTRIBUTE_NORMAL                   0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY                0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE              0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT            0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED               0x00000800  
#define FILE_ATTRIBUTE_OFFLINE                  0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED      0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED                0x00004000  
#define FILE_ATTRIBUTE_INTEGRITY_STREAM         0x00008000  
#define FILE_ATTRIBUTE_VIRTUAL                  0x00010000  
#define FILE_ATTRIBUTE_NO_SCRUB_DATA            0x00020000  
#define FILE_ATTRIBUTE_EA                       0x00040000  
#define FILE_ATTRIBUTE_PINNED                   0x00080000  
#define FILE_ATTRIBUTE_UNPINNED                 0x00100000  
#define FILE_ATTRIBUTE_RECALL_ON_OPEN           0x00040000  
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    0x00400000 

#define FILE_FLAG_WRITE_THROUGH                 0x80000000
#define FILE_FLAG_OVERLAPPED                    0x40000000
#define FILE_FLAG_NO_BUFFERING                  0x20000000
#define FILE_FLAG_RANDOM_ACCESS                 0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN               0x8000000
#define FILE_FLAG_DELETE_ON_CLOSE               0x4000000
#define FILE_FLAG_BACKUP_SEMANTICS              0x2000000
#define FILE_FLAG_POSIX_SEMANTICS               0x1000000
#define FILE_FLAG_SESSION_AWARE                 0x800000
#define FILE_FLAG_OPEN_REPARSE_POINT            0x200000
#define FILE_FLAG_OPEN_NO_RECALL                0x100000
#define FILE_FLAG_FIRST_PIPE_INSTANCE           0x80000

typedef struct _FILE_STANDARD_INFORMATION
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

//Source: http://processhacker.sourceforge.net
typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 0x1,
    FileFullDirectoryInformation = 0x2,
    FileBothDirectoryInformation = 0x3,
    FileBasicInformation = 0x4,
    FileStandardInformation = 0x5,
    FileInternalInformation = 0x6,
    FileEaInformation = 0x7,
    FileAccessInformation = 0x8,
    FileNameInformation = 0x9,
    FileRenameInformation = 0xa,
    FileLinkInformation = 0xb,
    FileNamesInformation = 0xc,
    FileDispositionInformation = 0xd,
    FilePositionInformation = 0xe,
    FileFullEaInformation = 0xf,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13,
    FileEndOfFileInformation = 0x14,
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FilePipeInformation = 0x17,
    FilePipeLocalInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileMailslotQueryInformation = 0x1a,
    FileMailslotSetInformation = 0x1b,
    FileCompressionInformation = 0x1c,
    FileObjectIdInformation = 0x1d,
    FileCompletionInformation = 0x1e,
    FileMoveClusterInformation = 0x1f,
    FileQuotaInformation = 0x20,
    FileReparsePointInformation = 0x21,
    FileNetworkOpenInformation = 0x22,
    FileAttributeTagInformation = 0x23,
    FileTrackingInformation = 0x24,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileValidDataLengthInformation = 0x27,
    FileShortNameInformation = 0x28,
    FileIoCompletionNotificationInformation = 0x29,
    FileIoStatusBlockRangeInformation = 0x2a,
    FileIoPriorityHintInformation = 0x2b,
    FileSfioReserveInformation = 0x2c,
    FileSfioVolumeInformation = 0x2d,
    FileHardLinkInformation = 0x2e,
    FileProcessIdsUsingFileInformation = 0x2f,
    FileNormalizedNameInformation = 0x30,
    FileNetworkPhysicalNameInformation = 0x31,
    FileIdGlobalTxDirectoryInformation = 0x32,
    FileIsRemoteDeviceInformation = 0x33,
    FileUnusedInformation = 0x34,
    FileNumaNodeInformation = 0x35,
    FileStandardLinkInformation = 0x36,
    FileRemoteProtocolInformation = 0x37,
    FileRenameInformationBypassAccessCheck = 0x38,
    FileLinkInformationBypassAccessCheck = 0x39,
    FileVolumeNameInformation = 0x3a,
    FileIdInformation = 0x3b,
    FileIdExtdDirectoryInformation = 0x3c,
    FileReplaceCompletionInformation = 0x3d,
    FileHardLinkFullIdInformation = 0x3e,
    FileIdExtdBothDirectoryInformation = 0x3f,
    FileDispositionInformationEx = 0x40,
    FileRenameInformationEx = 0x41,
    FileRenameInformationExBypassAccessCheck = 0x42,
    FileDesiredStorageClassInformation = 0x43,
    FileStatInformation = 0x44,
    FileMemoryPartitionInformation = 0x45,
    FileStatLxInformation = 0x46,
    FileCaseSensitiveInformation = 0x47,
    FileLinkInformationEx = 0x48,
    FileLinkInformationExBypassAccessCheck = 0x49,
    FileStorageReserveIdInformation = 0x4a,
    FileCaseSensitiveInformationForceAccessCheck = 0x4b,
    FileMaximumInformation = 0x4c
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef NTSTATUS NTAPI LDRLOADDLL(
    PWSTR               SearchPathw,
    PULONG              DllCharacteristics,
    PUNICODE_STRING     DllName,
    PVOID* BaseAddress
); typedef LDRLOADDLL* LPLDRLOADDLL;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY
(
    HANDLE      ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
); typedef NTALLOCATEVIRTUALMEMORY* LPNTALLOCATEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCLOSE(
    HANDLE Handle
); typedef NTCLOSE* LPNTCLOSE;

typedef NTSTATUS NTAPI NTFREEVIRTUALMEMORY
(
    HANDLE      ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       FreeType
); typedef NTFREEVIRTUALMEMORY* LPNTFREEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTOPENFILE(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions
); typedef NTOPENFILE* LPNTOPENFILE;

typedef NTSTATUS NTAPI NTPROTECTVIRTUALMEMORY
(
    HANDLE                  ProcessHandle,
    PVOID* BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG                   NewAccessProtection,
    PULONG                  OldAccessProtection
); typedef NTPROTECTVIRTUALMEMORY* LPNTPROTECTVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONFILE(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
); typedef NTQUERYINFORMATIONFILE* LPNTQUERYINFORMATIONFILE;

typedef NTSTATUS NTAPI NTREADFILE(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,   //PIO_APC_ROUTINE//This parameter is reserved. Device and intermediate drivers should set this pointer to NULL.
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
); typedef NTREADFILE* LPNTREADFILE;

typedef NTSTATUS NTAPI NTWRITEVIRTUALMEMORY
(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    ULONG   NumberOfBytesToWrite,         //ULONG NumberOfBytesToWrite
    PULONG  NumberOfBytesWritten         //PULONG NumberOfBytesWritten 
); typedef NTWRITEVIRTUALMEMORY* LPNTWRITEVIRTUALMEMORY;

typedef NTSTATUS NTAPI RTLINITUNICODESTRING(
    PUNICODE_STRING     DestinationString,                                  //_Out_
    PWSTR               SourceString                                                  //_In_opt_z_
); typedef RTLINITUNICODESTRING* LPRTLINITUNICODESTRING;

//-----------------------------------------------------------------------------------

__forceinline WCHAR __cdecl ToLowerW(WCHAR wideChar)
{
    if (wideChar > 0x40 && wideChar < 0x5B)
    {
        return wideChar + 0x20;
    }
    return wideChar;
}

__forceinline char __cdecl ToLowerA(char baseChar)
{
    if (baseChar > 96 && baseChar < 123)
    {
        baseChar -= 32;
    }
    return baseChar;
}

__forceinline int __cdecl StringLengthA(char* baseStr)
{
    int length;
    for (length = 0; baseStr[length] != '\0'; length++) {}
    return length;
}

__forceinline int __cdecl StringLengthW(WCHAR* wideStr) {
    int length;
    for (length = 0; wideStr[length] != '\0'; length++) {}
    return length;
}

__forceinline BOOLEAN __cdecl CompareUnicode(PWSTR wideStr1, PWSTR wideStr2)
{
    for (int i = 0; i < StringLengthW(wideStr1); i++)
    {
        if (ToLowerW(wideStr1[i]) != ToLowerW(wideStr2[i]))
            return FALSE;
    }
    return TRUE;
}

__forceinline BOOLEAN __cdecl CompareAnsi(char* baseStr1, char* baseStr2)
{
    for (int i = 0; i < StringLengthA(baseStr1); i++)
    {
        if (ToLowerA(baseStr1[i]) != ToLowerA(baseStr2[i]))
            return FALSE;
    }
    return TRUE;
}

__forceinline char* __cdecl Separator(char* fullName)
{
    SIZE_T len = (SIZE_T)StringLengthA(fullName);

    for (SIZE_T i = 0; i < len; i++)
    {
        if (fullName[i] == '.')
        {
            return &fullName[i + 1];
        }
    }
    return NULL_PTR;
}

__forceinline BOOL __cdecl StringMatches(WCHAR* wideStr1, WCHAR* wideStr2)
{
    if (wideStr1 == NULL_PTR || wideStr2 == NULL_PTR || StringLengthW(wideStr1) != StringLengthW(wideStr2))
    {
        return FALSE;
    }

    for (int i = 0; wideStr1[i] != '\0' && wideStr2[i] != '\0'; i++)
    {
        if (ToLowerW(wideStr1[i]) != ToLowerW(wideStr2[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

__forceinline BOOL __cdecl StringMatchesA(CHAR* wideStr1, CHAR* wideStr2)
{
    if (wideStr1 == NULL_PTR || wideStr2 == NULL_PTR || StringLengthA(wideStr1) != StringLengthA(wideStr2))
    {
        return FALSE;
    }

    for (int i = 0; wideStr1[i] != '\0' && wideStr2[i] != '\0'; i++)
    {
        if (ToLowerA(wideStr1[i]) != ToLowerA(wideStr2[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static PVOID PEBAddress = NULL_PTR;

__forceinline LPVOID __cdecl NtCurrentPeb(void)
{
#if defined(_WIN64)
    //UINT64 pPebLocation = __readgsqword(0x60);
    //return (LPVOID)pPebLocation;
    if (PEBAddress == NULL_PTR)
        PEBAddress = (PVOID)__readgsqword(0x60);
    return PEBAddress;
#else
    //UINT32 pPebLocation = __readfsdword(0x30);
    //return (LPVOID)pPebLocation;
    if (PEBAddress == NULL_PTR)
        PEBAddress = (PVOID)__readfsdword(0x30);
    return PEBAddress;
#endif
}

static PVOID TEBAddress = NULL_PTR;

__forceinline LPVOID __cdecl NtCurrentTIBOrTEB(void)
{
#if defined(_WIN64)
    //UINT64 pTibOrTEBLocation = __readgsqword(0x30);
    //return (LPVOID)pTibOrTEBLocation;
    if (TEBAddress == NULL_PTR)
        TEBAddress = (LPVOID)__readgsqword(0x30);
    return TEBAddress;
#else
    //UINT32 pTibOrTEBLocation = __readfsdword(0x18);
    //return (LPVOID)pTibOrTEBLocation;
    if (TEBAddress == NULL_PTR)
        TEBAddress = (LPVOID)__readfsdword(0x18);
    return TEBAddress;
#endif
}

#if !defined(_WIN64)
__forceinline LPVOID __cdecl FastSysCallWoW64(void) {
    UINT32 wow64Transition = __readfsdword(0xC0);
    return (LPVOID)wow64Transition;
}
#endif

#define NtCurrentProcessId() (((PTEB)NtCurrentTIBOrTEB())->ClientId.UniqueProcess)
#define NtCurrentThreadId() (((PTEB)NtCurrentTIBOrTEB())->ClientId.UniqueThread)

__forceinline PVOID __cdecl GetModuleBaseAddress(PWSTR wideName)
{
    PPEB pPeb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)pPeb->LdrData;

    for (PLDR_DATA_ENTRY pLdrDataEntry = (PLDR_DATA_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->BaseAddress != NULL_PTR; pLdrDataEntry = (PLDR_DATA_ENTRY)pLdrDataEntry->InLoadOrderModuleList.Flink)
    {
        if (CompareUnicode(wideName, pLdrDataEntry->BaseDllName.Buffer))
            return pLdrDataEntry->BaseAddress;
    }
    return NULL_PTR;
}

__forceinline LPVOID __cdecl GetProcedureAddressNt(char* sProcName)//, DWORD ordinal)
{
    WCHAR nt[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    DWORD_PTR pBaseAddr = (DWORD_PTR)GetModuleBaseAddress(nt);//L"ntdll.dll\0"
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
            return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
        }
    }
    return NULL;
}

__forceinline PVOID __cdecl MallocCustom(PSIZE_T size)
{
    char ntAllocate[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', '\0' };
    LPNTALLOCATEVIRTUALMEMORY pNtAllocate = (LPNTALLOCATEVIRTUALMEMORY)GetProcedureAddressNt(ntAllocate);//"NtAllocateVirtualMemory\0"
    PVOID pAllocated = NULL_PTR;
    pNtAllocate((HANDLE)(-1), &pAllocated, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return pAllocated;
}

__forceinline char* __cdecl ReverseSeparator(char* fullName)
{
    SIZE_T len = StringLengthA(fullName);

    int indexPoint = 5;//. d l l \0

    for (SIZE_T i = 0; i < len; i++)
    {
        if (fullName[i] == '.')
        {
            indexPoint += (int)i;
            break;
        }
    }
    DWORD_PTR size = (DWORD_PTR)((sizeof(char) * indexPoint));
    char* name = (char*)MallocCustom(&size);
    if (name != NULL_PTR)
    {
        for (int i = 0; i < indexPoint; i++)
            name[i] = fullName[i];

        name[indexPoint - 5] = '.';
        name[indexPoint - 4] = 'd';
        name[indexPoint - 3] = 'l';
        name[indexPoint - 2] = 'l';
        name[indexPoint - 1] = '\0';
        return name;
    }
    return NULL_PTR;
}

__forceinline WCHAR* __cdecl CharToWCharT(char* baseChar)
{
    int length = StringLengthA(baseChar);

    DWORD_PTR size = (DWORD_PTR)(sizeof(WCHAR) * length + 2);
    WCHAR* wideChar = (WCHAR*)MallocCustom(&size);

    if (wideChar != NULL_PTR)
    {
        for (int i = 0; i < length; i++)
        {
            wideChar[i] = (WCHAR)(baseChar[i]);
        }
        wideChar[length] = '\0';
        return (WCHAR*)wideChar;
    }
    return NULL_PTR;
}

//This function is a rework of function of Sektor7 Malware Development Intermediate Section 2. PE madness
//with https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp
__forceinline LPVOID __cdecl GetProcedureAddress(HMODULE hMod, char* sProcName)
{
    char ntFree[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    LPNTFREEVIRTUALMEMORY pNtFree = (LPNTFREEVIRTUALMEMORY)GetProcedureAddressNt(ntFree);//"NtFreeVirtualMemory\0"
    DWORD_PTR pBaseAddr = (DWORD_PTR)hMod;
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    if (((DWORD_PTR)sProcName >> 16) == 0)
    {
        WORD ordinal = (WORD)sProcName & 0xFFFF;
        DWORD Base = pExportDirAddr->Base;		

        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
        {
            return NULL_PTR;
        }
        return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    else
    {    
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++)
        {
            char* sTmpFuncName = (char*)(pBaseAddr + (DWORD_PTR)pFuncNameTbl[i]);

            if (CompareAnsi(sProcName, sTmpFuncName) == TRUE)
            {
                unsigned short nameOrdinal = ((unsigned short*)(((unsigned long long)pBaseAddr) + pExportDirAddr->AddressOfNameOrdinals))[i];
                unsigned int addr = ((unsigned int*)(((unsigned long long)pBaseAddr) + pExportDirAddr->AddressOfFunctions))[nameOrdinal];

                if (addr > pExportDataDir->VirtualAddress && addr < pExportDataDir->VirtualAddress + pExportDataDir->Size)
                {
                    char* forwardStr = (char*)(pBaseAddr + addr);
                    char* funcName = Separator(forwardStr);
                    char* moduleName = ReverseSeparator(forwardStr);

                    SIZE_T size = ((SIZE_T)(StringLengthA(moduleName) * sizeof(WCHAR) + 2));
                    PWSTR moduleUnicode = MallocCustom(&size);
                    moduleUnicode = CharToWCharT(moduleName);
                    PVOID modAddr = GetModuleBaseAddress(moduleUnicode);

                    pNtFree((HANDLE)(-1), &moduleUnicode, &size, MEM_RELEASE);
                    size = ((SIZE_T)StringLengthA(moduleName));
                    pNtFree((HANDLE)(-1), &moduleName, &size, MEM_RELEASE);

                    return GetProcedureAddress((HMODULE)modAddr, funcName);
                }
                else
                {
                    return (LPVOID)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
                }
            }
        }
    }
    return NULL;
}