; ----------------------------------------------------------------------------------------------------------- 
; Variables (we don't currently use these, this is just an example of how to populate the data segment)
; ----------------------------------------------------------------------------------------------------------- 
_DATA SEGMENT
 hello_msg db "Hello world", 0
_DATA ENDS
 
; ----------------------------------------------------------------------------------------------------------- 
; Text or code segment
; ----------------------------------------------------------------------------------------------------------- 
_TEXT SEGMENT

; The PUBLIC modifier will make your function visible and callable outside
PUBLIC adbg_BeingDebuggedPEBx64
PUBLIC adbg_NtGlobalFlagPEBx64
PUBLIC adbg_QueryPerformanceCounterx64
PUBLIC adbg_GetTickCountx64
PUBLIC adbg_RDTSCx64
PUBLIC adbg_Int2Dx64
PUBLIC adbg_Int3x64
PUBLIC adbg_SingleStepExceptionx64

adbg_BeingDebuggedPEBx64 PROC
    xor rax, rax                ; clear eax
    mov rax, gs:[60h]           ; reference start of the PEB
    mov rax, [rax + 02h]        ; PEB+2 points to BeingDebugged
    and rax, 0FFh               ; only reference one byte
    ret	                        ; return into 'rax' which puts BeingDebugged value into 'found'
adbg_BeingDebuggedPEBx64 ENDP

adbg_NtGlobalFlagPEBx64 PROC
    xor rax, rax                ; clear eax
    mov rax, gs:[60h]           ; Reference start of the PEB
    mov rax, [rax + 0BCh]       ; PEB+0xBC points to NtGlobalFlag
    and rax, 70h                ; check three flags
    ret	                        ; return flag value into 'rax' which puts into 'found'
adbg_NtGlobalFlagPEBx64 ENDP

adbg_QueryPerformanceCounterx64 PROC
    xor rax, rax                ; this
    push rax                    ; is
    push rcx                    ; just
    pop rax                     ; junk
    pop rcx                     ; code
    sub rcx, rax                ; use
    shl rcx, 4                  ; whatever
    ret
adbg_QueryPerformanceCounterx64 ENDP

adbg_GetTickCountx64 PROC
    xor rax, rax                ; this
    push rax                    ; is
    push rcx                    ; just
    pop rax                     ; junk
    pop rcx                     ; code
    sub rcx, rax                ; use
    shl rcx, 4                  ; whatever
    ret
adbg_GetTickCountx64 ENDP

adbg_RDTSCx64 PROC
                                ; Note: On Windows, the x64 calling convention places the first argument (a pointer to TimeKeeper) in RCX
                                ; We must avoid clobbering RCX. If we need to clobber RCX for some reason, we'll have to save it in another
                                ; register, the stack, or somewhere else. 
    rdtsc                       ; First time check!
                                ; rdtsc stores result across EDX:EAX on x86
                                ; on x64 rdtsc does roughly the same, but it clears the high-order 32 bits of RDX and RAX
    mov [rcx + 00h], rdx        ; TimeKeeper.timeUpperA
    mov [rcx + 08h], rax        ; TimeKeeper.timeLowerA
    xor rax, rax                ; this
    mov rax, 5                  ; is 
    shr rax, 2                  ; just
    sub rax, rbx                ; junk
    cmp rax, rcx                ; code
    rdtsc                       ; Second time check!
    mov [rcx + 10h], rdx        ; TimeKeeper.timeUpperB
    mov [rcx + 18h], rax        ; TimeKeeper.timeLowerB
    ret
adbg_RDTSCx64 ENDP

adbg_Int2Dx64 PROC
    int 2Dh                     ; interrupt 0x2D kernel breakpoint
    nop                         ;
adbg_Int2Dx64 ENDP

adbg_Int3x64 PROC
    int 3                       ; 0xCC breakpoint
adbg_Int3x64 ENDP

adbg_SingleStepExceptionx64 PROC
    pushfq                      ; save RFLAGS register
    or byte ptr[rsp + 1], 1     ; set trap flag in RFLAGS
    popfq                       ; restore RFLAGS register
    ret;                        ; 
adbg_SingleStepExceptionx64 ENDP


_TEXT ENDS
 
END
