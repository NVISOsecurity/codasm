global main
extern process
section .text

    main:
        jmp shellcodePush

    decoder:
        pop rcx                     ; Param 1: CA_PAYLOAD
        sub rsp, 32                 ; Allocate 32-byte shadow space
        
        mov edx, %CA_PAYLOAD_LEN%   ; Param 2: CA_PAYLOAD_LEN
        mov r8, %CA_OUTPUT_LEN%     ; Param 3: CA_OUTPUT_LEN
        mov r9, %XOR%               ; Param 4: XOR Key

        call process

        ; Clean up the stack
        add rsp, 32
        ret

    shellcodePush:
        call decoder ; moves return address onto stack
        incbin "codasm_payload.bin"
