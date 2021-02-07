; ----------------------------------------------------------------------------------------------------------- 
; Variables
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

adbg_BeingDebuggedPEBx64 PROC
    xor rax, rax                ; clear eax
    mov rax, gs:[60h]           ; reference start of the PEB
    mov rax, [rax + 02h]        ; PEB+2 points to BeingDebugged
    and rax, 0FFh               ; only reference one byte
    ret	                        ; return into 'rax' which puts BeingDebugged value into 'found'
adbg_BeingDebuggedPEBx64 ENDP

adbg_NtGlobalFlagPEBx64 PROC
    xor rax, rax            ; clear eax
    mov rax, gs:[60h]       ; Reference start of the PEB
    mov rax, [rax + 0BCh]   ; PEB+0x68 points to NtGlobalFlags
    and rax, 70h            ; check three flags
    ret	                    ; return into 'rax' which puts BeingDebugged value into 'found'
adbg_NtGlobalFlagPEBx64 ENDP

adbg_QueryPerformanceCounterx64 PROC
    xor rax, rax            ; this
    push rax                ; is
    push rcx                ; just
    pop rax                 ; junk
    pop rcx                 ; code
    sub rcx, rax            ; use
    shl rcx, 4              ; whatever
    ret
adbg_QueryPerformanceCounterx64 ENDP

adbg_GetTickCountx64 PROC
    xor rax, rax            ; this
    push rax                ; is
    push rcx                ; just
    pop rax                 ; junk
    pop rcx                 ; code
    sub rcx, rax            ; use
    shl rcx, 4              ; whatever
    ret
adbg_GetTickCountx64 ENDP

_TEXT ENDS
 
END
