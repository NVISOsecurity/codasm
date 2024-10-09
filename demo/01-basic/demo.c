
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include "popcalc.h" // Holds `buf`, our shellcode

typedef int (*fptr)();

int main()
{
    uint8_t *memory = NULL;
    DWORD oldProtect;
    DWORD errorCode;
    BOOL result;
    fptr func;
    int returnValue;

    printf("[*] Allocating %i bytes... \n", sizeof(buf));
    memory = (unsigned char *)malloc(sizeof(buf));
    if (!memory)
    {
        printf("[!] Failed to alloc %i bytes!\n", sizeof(buf));
        return 1;
    }

    printf("[*] Protecting section to be RWX... \n");
    result = VirtualProtect((LPVOID)memory, sizeof(buf), PAGE_EXECUTE_READWRITE, &oldProtect);
    errorCode = GetLastError();
    if (!result)
    {
        printf("[!] Failed to VP(RWX): %i \n", errorCode);
        return -1;
    }
    
    printf("[*] Copying data to RWX'ed memory... \n");
    memcpy(memory, buf, sizeof(buf));

    func = (fptr)memory;
    returnValue = func();
    printf("[+] Code terminated, return value: %i \n", returnValue);

    return 0;
}