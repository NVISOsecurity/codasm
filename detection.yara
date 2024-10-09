import "pe"
import "math"


private rule IsPE
{
    meta:
        description = "Tests whether the file starts with the MZ header."
        author = "Moritz Thomas"
        date = "2024-07-24"

    condition:
        uint16(0) == 0x5A4D
}

private rule ExampleUsage
{
    meta:
        description = "Detects malloc and invoking the decode function, passing in references to the .data section"
        author = "Moritz Thomas"
        date = "2024-07-24"
    
    strings:
        $AllocDecode = {
            8b 0d ?? ?? ?? ??   // MOV ECX, dword ptr [DAT_1400fb070]
            89 4c 24 ??         // MOV dword ptr [RSP + 0x3c], ECX
            e8 ?? ?? ?? ??      // CALL MSVCRT.DLL::malloc
                               // ECX = DAT_1400fb070
                               // [RSP + 0x3c] = ECX
                               // malloc()
            8b 15 ?? ?? ?? ??   // MOV EDX, dword ptr [DAT_1400fb080]
            44 8b 4c 24 ??      // MOV R9D, dword ptr [RSP + 0x3c]
                               // EDX = DAT_1400fb080
                               // R9D = [RSP + 0x3c]
            48 8d 0d ?? ?? ?? ?? // LEA RCX, [FUN_140001460]
            48 89 c3            // MOV RBX, RAX
            48 8b 05 ?? ?? ?? ?? // MOV RAX, qword ptr [DAT_1400fb090]
            49 89 d8            // MOV R8, RBX
            48 89 44 24 ??      // MOV qword ptr [RSP + 0x20], RAX
                               // RCX = &FUN_140001460
                               // RBX = RAX
                               // RAX = DAT_1400fb090
                               // R8 = RBX
                               // [RSP + 0x20] = RAX
            e8 ?? ?? ?? ??      // CALL FUN_1400f9cf0
                               // FUN_1400f9cf0()
            89 c2               // MOV EDX, EAX
            85 c0               // TEST EAX, EAX
            79 13               // JNS LAB_1400fac7b
                               // EDX = EAX
                               // if (EAX >= 0) goto LAB_1400fac7b
            48 8d 0d ?? ?? ?? ?? // LEA RCX, [LAB_1400fc0e3]
            e8 ?? ?? ?? ??      // CALL FUN_1400faae0
                               // RCX = &LAB_1400fc0e3
                               // FUN_1400faae0()
            b8 01 00 00 00      // MOV EAX, 0x1
            eb ??               // JMP LAB_1400faca3
                               // EAX = 1
                               // goto LAB_1400faca3
            83 f8 42            // CMP EAX, 0x42
            75 ??               // JNZ LAB_1400fac8a
                               // if (EAX != 0x42) goto LAB_1400fac8a
            b9 22 00 00 00      // MOV ECX, 0x22
            e8 ?? ?? ?? ??      // CALL FUN_140001460
                               // ECX = 0x22
                               // FUN_140001460()
        }
        // if (iVar2 == 0x42) FUN_140001460(0x22, 0x42);
        $PseudoCall= {
            83 f8 42          // CMP EAX, 0x42
            75 ??             // JNZ LAB_1400FACA3
            b9 22 00 00 00    // MOV ECX, 0x22
            e8 ?? ?? ?? ??    // CALL FUN_140001460
        }

    condition:
        IsPE and $AllocDecode and $PseudoCall
}

private rule Decode
{
    meta:
        description = "Detects parameter validation (null-checks), returning -2 and performing a pseudo call RBX(22h)"
        author = "Moritz Thomas"
        date = "2024-07-24"
    
    strings:
        $NullTest = {
            48 85 c9 // TEST    param_1,param_1
            74 ??    // JZ      LAB_1400f9d76
            4d 85 c0 // TEST    param_3,param_3
            74 ??    // JZ      LAB_1400f9d76
        }
        $ReturnMinusTwo = {
            b8 fe ff ff ff  // MOV  EAX,0xfffffffe
        }
        $PseudoCall = {
            b9 22 00 00 00  // MOV  ECX,0x22
            ff d3           // CALL RBX
        }

    condition:
        IsPE and $NullTest and $ReturnMinusTwo and $PseudoCall
}

private rule PEAnalysis
{
    meta:
        description = "Detects PE files with very large .text sections (>=90%) that have reasonable entropy (5.0 < e(.text) < 7.0)."
        author = "Moritz Thomas"
        date = "2024-07-24"

    condition:
        IsPE and // Check for MZ header
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".text"  and
            pe.sections[i].raw_data_size > (filesize * 0.9) and
            math.in_range(
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size),
                5.0, 7.0
            )
            
        )
}

private rule Shellcode
{
    meta:
        description = "Detects the ASM and C shellcode stubs."
        author = "Moritz Thomas"
        date = "2024-10-09"
    
    strings:
        $CallNReturn420 = {
            ff d3                	// call   *%rbx // ((fptr)(pAddress))();
            b8 20 04 00 00       	// mov    $0x420,%eax // return 0x420;
            48 83 c4 48          	// add    $0x48,%rsp
            5b 5e 5f 5d 41 5c 41 5d // pop    %rbx, %rsi, %rdi, %rbp, %r12, %r13
            c3                      // ret
        }

        $AsmStub = {
            eb 24                	// jmp    shellcodePush
            59                   	// pop    rcx
            48 83 ec 20          	// sub    rsp,0x20
            ba 56 ?? ?? ??       	// mov    edx,CA_PAYLOAD_LEN
            41 b8 ?? ?? ?? ??    	// mov    r8d,CA_OUTPUT_LEN
            49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 	// movabs r9,XOR_KEY
            e8 3f ?? ?? ??       	// call   0x1260
            48 83 c4 20          	// add    rsp,0x20
            c3                   	// ret
            e8 d7 ff ff ff       	// call   decoder
        }

    condition:
        $CallNReturn420 or $AsmStub
}

rule CODASMed
{
    condition:
        ExampleUsage or (Decode and PEAnalysis) or Shellcode
}