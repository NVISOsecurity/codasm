#include "codasm_decoder.h"
#include "codasm_payload.h"
#include <windows.h>
#include <stdio.h>

int main() {
    uint8_t* output = (uint8_t*)malloc(CA_OUTPUT_LEN);
    int32_t res = 0;
    if ((res = decode((uint8_t*)CA_PAYLOAD, CA_PAYLOAD_LEN, output, CA_OUTPUT_LEN, CA_XORKEY)) < 0) {
        printf("[!] Failed to decode: %i\n", res);
        return 1; // Some doo-doo happened, breakpoint the decode method
    }
    printf("[+] Successfully decoded payload!\n");
    
    return 0;
}