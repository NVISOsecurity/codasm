#ifndef RUN_SHELLCODE
#define RUN_SHELLCODE

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

typedef int (*fptr)();

int32_t run(uint8_t *shellcode, uint32_t size, BOOL alloc, BOOL rwx)
{
    unsigned char *memory = NULL;
    if (alloc)
    {
        printf("[*] Allocating %i bytes... \n", size);
        memory = (unsigned char *)malloc(size);
        if (!memory)
        {
            printf("[!] Failed to alloc %i bytes!\n", size);
            return 1;
        }
    }
    else
    {
        memory = shellcode;
    }

    if (rwx)
    {
        DWORD flOldProtect;
        printf("[*] Protecting section to be RWX... \n");
        BOOL res = VirtualProtect((LPVOID)memory, size, PAGE_EXECUTE_READWRITE, &flOldProtect);
        DWORD err = GetLastError();
        if (!res)
        {
            printf("[!] Failed to VP(RWX): %i \n", err);
            return -1;
        }
    }

    if (alloc)
    {
        printf("[*] Copying data to RWX'ed memory... \n");
        memcpy(memory, shellcode, size);
    }

    printf("[*] Calling code... \n");

    int ret = 0;
    fptr func = (fptr)memory;
    ret = func();
    printf("[+] Code terminated, return value: %i \n", ret);

    return 0;
}

#endif // RUN_SHELLCODE