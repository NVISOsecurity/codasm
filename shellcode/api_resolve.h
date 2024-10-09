// Based on: https://github.com/thefLink/DeepSleep/blob/main/src/ApiResolve.h
#pragma once

#include <stdint.h>
#include "windows.h"

#define FAIL 0
#define SUCCESS 1

uint64_t getFunctionPtr(unsigned long, unsigned long);
static uint64_t getDllBase(unsigned long);
static uint64_t loadDll(unsigned long);
static uint64_t loadDll_byName(char *);
static uint64_t parseHdrForPtr(uint64_t, unsigned long);
static uint64_t followExport(char *, unsigned long);

static unsigned long djb2(unsigned char *);
static unsigned long unicode_djb2(const wchar_t *str);
static unsigned long xor_hash(unsigned long);
static WCHAR *toLower(WCHAR *str);

//%HASHES%

typedef HANDLE(WINAPI *CREATETHREAD)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI *VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);

typedef PCSTR(WINAPI *STRSTRA)(PCSTR, PCSTR);

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;

uint64_t
getFunctionPtr(unsigned long crypted_dll_hash, unsigned long crypted_function_hash)
{

    uint64_t dll_base = 0x00;
    uint64_t ptr_function = 0x00;

    dll_base = getDllBase(crypted_dll_hash);
    if (dll_base == 0)
    {
        dll_base = loadDll(crypted_dll_hash);
        if (dll_base == 0)
            return FAIL;
    }

    ptr_function = parseHdrForPtr(dll_base, crypted_function_hash);

    return ptr_function;
}

static uint64_t
loadDll(unsigned long crypted_dll_hash)
{

    uint64_t kernel32_base = 0x00;
    uint64_t fptr_loadLibary = 0x00;
    uint64_t ptr_loaded_dll = 0x00;

    kernel32_base = getDllBase(CRYPTED_HASH_KERNEL32);
    if (kernel32_base == 0x00)
        return FAIL;

    fptr_loadLibary = parseHdrForPtr(kernel32_base, CRYPTED_HASH_LOADLIBRARYA);
    if (fptr_loadLibary == 0x00)
        return FAIL;

    if (crypted_dll_hash == CRYPTED_HASH_SHLWAPI)
    {
        char dll_name[] = {'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x00};
        ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
    }

    return ptr_loaded_dll;
}

static uint64_t
loadDll_byName(char *dll_name)
{

    uint64_t kernel32_base = 0x00;
    uint64_t fptr_loadLibary = 0x00;
    uint64_t ptr_loaded_dll = 0x00;

    kernel32_base = getDllBase(CRYPTED_HASH_KERNEL32);
    if (kernel32_base == 0x00)
        return FAIL;

    fptr_loadLibary = parseHdrForPtr(kernel32_base, CRYPTED_HASH_LOADLIBRARYA);
    if (fptr_loadLibary == 0x00)
        return FAIL;

    ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);

    return ptr_loaded_dll;
}

static uint64_t
parseHdrForPtr(uint64_t dll_base, unsigned long crypted_function_hash)
{

    PIMAGE_NT_HEADERS nt_hdrs = NULL;
    PIMAGE_DATA_DIRECTORY data_dir = NULL;
    PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

    uint32_t *ptr_exportadrtable = 0x00;
    uint32_t *ptr_namepointertable = 0x00;
    uint16_t *ptr_ordinaltable = 0x00;

    uint32_t idx_functions = 0x00;

    unsigned char *ptr_function_name = NULL;

    nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
    data_dir = (PIMAGE_DATA_DIRECTORY)&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    export_dir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + (uint64_t)data_dir->VirtualAddress);

    ptr_exportadrtable = (uint32_t *)(dll_base + (uint64_t)export_dir->AddressOfFunctions);
    ptr_namepointertable = (uint32_t *)(dll_base + (uint64_t)export_dir->AddressOfNames);
    ptr_ordinaltable = (uint16_t *)(dll_base + (uint64_t)export_dir->AddressOfNameOrdinals);

    for (idx_functions = 0; idx_functions < export_dir->NumberOfNames; idx_functions++)
    {

        ptr_function_name = (unsigned char *)dll_base + (ptr_namepointertable[idx_functions]);
        if (djb2(ptr_function_name) == xor_hash(crypted_function_hash))
        {

            WORD nameord = ptr_ordinaltable[idx_functions];
            DWORD rva = ptr_exportadrtable[nameord];

            if (dll_base + rva >= dll_base + data_dir->VirtualAddress && dll_base + rva <= dll_base + data_dir->VirtualAddress + (uint64_t)data_dir->Size)
            {
                // This is a forwarded export

                char *ptr_forward = (char *)(dll_base + rva);
                return followExport(ptr_forward, crypted_function_hash);
            }

            return dll_base + rva;
        }
    }

    return FAIL;
}

static uint64_t followExport(char *ptr_forward, unsigned long crypted_function_hash)
{

    STRSTRA _StrStrA = (STRSTRA)getFunctionPtr(CRYPTED_HASH_SHLWAPI, CRYPTED_HASH_STRSTRA);

    if (_StrStrA == 0x00)
        return FAIL;

    char del[] = {'.', 0x00};
    char *pos_del = 0x00;
    char forward_dll[MAX_PATH] = {0};
    char forward_export[MAX_PATH] = {0};
    unsigned long forward_export_hash = 0x00;
    uint8_t i = 0;
    uint64_t fwd_dll_base = 0x00, forwarded_export = 0x00;

    while (*ptr_forward)
        forward_dll[i++] = *ptr_forward++;

    pos_del = (char *)_StrStrA(forward_dll, del);
    if (pos_del == 0)
        return FAIL;

    *(char *)(pos_del++) = 0x00;
    i = 0;
    while (*pos_del)
        forward_export[i++] = *pos_del++;

    forward_export_hash = xor_hash(djb2((unsigned char *)forward_export));

    fwd_dll_base = getDllBase(xor_hash(djb2((unsigned char *)forward_dll)));
    if (fwd_dll_base == 0x00)
    {
        fwd_dll_base = loadDll_byName(forward_dll);
        if (fwd_dll_base == 0x00)
            return FAIL;
    }

    forwarded_export = parseHdrForPtr(fwd_dll_base, forward_export_hash);

    return forwarded_export;
}

static uint64_t
getDllBase(unsigned long crypted_dll_hash)
{

    _PPEB ptr_peb = NULL;
    PPEB_LDR_DATA ptr_ldr_data = NULL;
    PLDR_DATA_TABLE_ENTRY ptr_module_entry = NULL, ptr_start_module = NULL;
    PUNICODE_STR dll_name = NULL;

    ptr_peb = (_PEB *)__readgsqword(0x60);
    ptr_ldr_data = ptr_peb->pLdr;
    ptr_module_entry = ptr_start_module = (PLDR_DATA_TABLE_ENTRY)ptr_ldr_data->InMemoryOrderModuleList.Flink;

    do
    {

        dll_name = &ptr_module_entry->BaseDllName;

        if (dll_name->pBuffer == NULL)
            return FAIL;

        if (unicode_djb2(toLower(dll_name->pBuffer)) == xor_hash(crypted_dll_hash))
            return (uint64_t)ptr_module_entry->DllBase;

        ptr_module_entry = (PLDR_DATA_TABLE_ENTRY)ptr_module_entry->InMemoryOrderModuleList.Flink;

    } while (ptr_module_entry != ptr_start_module);

    return FAIL;
}

static unsigned long
djb2(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

unsigned long
unicode_djb2(const wchar_t *str)
{

    unsigned long hash = 5381;
    DWORD val;

    while (*str != 0)
    {
        val = (DWORD)*str++;
        hash = ((hash << 5) + hash) + val;
    }

    return hash;
}

unsigned long
xor_hash(unsigned long hash)
{
    return hash ^ CRYPT_KEY;
}

static WCHAR *
toLower(WCHAR *str)
{

    WCHAR *start = str;

    while (*str)
    {

        if (*str <= L'Z' && *str >= 'A')
        {
            *str += 32;
        }

        str += 1;
    }

    return start;
}