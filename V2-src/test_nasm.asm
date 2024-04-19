section .text
global Spoof
;extern Setup
;extern NtWait

Spoof:
    pop r12                         ; Real return address in r12
    ;pop rax                        ; Real return address in rax

    mov r10, rdi                    ; Store original rdi in r10
    mov r11, rsi                    ; Store original rsi in r11

    mov rdi, [rsp + 32]             ; Storing struct in the rdi ; 5th arg of spoof() = &SpoofStruct
    mov rsi, [rsp + 40]             ; Storing function to call  ; 6th arg of spoof() = AddrOfNtAPI Func

    ; Storing our original registers
    mov [rdi + 24], r10             ; Storing original rdi into PRM.rdi
    mov [rdi + 88], r11             ; Storing original rsi into PRM.rsi
    mov [rdi + 96], r12             ; Storing original r12 into PRM.r12
    mov [rdi + 104], r13            ; Storing original r13 into PRM.r13
    mov [rdi + 112], r14            ; Storing original r14 into PRM.r14
    mov [rdi + 120], r15            ; Storing original r15 into PRM.r15

    ; only: pop r12 => instead of `pop rax` and `mov r12, rax` can also be done!

    ; Prepping to move stack args
    xor r11, r11                    ; Nulling it : r11 will hold the # of args that have been "pushed"
    mov r13, [rsp + 30h]            ; r13 will hold the # of args total that will be pushed

    mov r14, 200h                   ; r14 will hold the offset we need to push stuff;  as fake frames start with a sub rsp 200h
    add r14, 8
    add r14, [rdi + 56]             ; stack size of RUTS = PRM.RUTS_ss
    add r14, [rdi + 48]             ; stack size of BTIT = PRM.BTIT_ss
    add r14, [rdi + 32]             ; stack size of our gadget frame = PRM.Gadget_ss
    sub r14, 20h                    ; first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time

    mov r10, rsp
    add r10, 30h                    ; offset of stack arg added to rsp ; rsp updated!

looping:
    xor r15, r15                    ; r15 will hold the offset + rsp base
    cmp r11, r13                    ; comparing # of stack args added vs # of stack args we need to add
    je finish                       ; If required args matched => then Jumps to finish
                                    ; Else adds another arg then goes through this check (cmp r11, r13)

    ; Getting location to move the stack arg to
    sub r14, 8                      ; 1 arg means r11 is 0, r14 already 0x28 offset.
    mov r15, rsp                    ; get current stack base
    sub r15, r14                    ; subtract offset

    ; Procuring the stack arg
    add r10, 8
    push qword [r10]
    pop qword [r15]                 ; move the stack arg into the right location

    ; Increment the counter and loop back in case we need more args
    add r11, 1
    jmp looping

finish:
    ; Creating a big 320 byte working space
    sub rsp, 200h

    ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart.
    ; Need to figure out why this cuts off the call stack
    push 0

    ; RtlUserThreadStart + 0x14 frame
    sub rsp, [rdi + 56]
    mov r11, [rdi + 64]
    mov [rsp], r11

    ; BaseThreadInitThunk + 0x21 frame
    sub rsp, [rdi + 32]
    mov r11, [rdi + 40]
    mov [rsp], r11

    ; Gadget frame
    sub rsp, [rdi + 48]
    mov r11, [rdi + 80]
    mov [rsp], r11

    ; Adjusting the param struct for the fixup
    mov r11, rsi                    ; Copying function to call into r11
    mov [rdi + 8], r12              ; Real return address (in r12) is now moved into PRM.OG_retaddr
    mov [rdi + 16], rbx             ; original rbx is stored into PRM.rbx 
    lea rbx, [fixup]                ; fixup asm function's address is moved into rbx register ; why rbx? -> rbx register = addr of PRM struct = PRM.Fixup
    mov [rdi], rbx                  ; Fixup member (PRM.Fixup) now holds the address of fixup asm function
    mov rbx, rdi                    ; Address of param struct (Fixup) is moved into rbx

    ; Syscall stuff. Shouldn't affect performance even if a syscall isn't made
    mov r10, rcx
    mov rax, [rdi + 72]             ; PRM.ssn
    jmp r11

fixup:
    mov rcx, rbx                    ; rbx (PRM.rbx) : Contains addr of this PRM struct

    add rsp, 200h                   ; Big frame thing (Random Size. Just Worked!)
    add rsp, [rbx + 48]             ; Stack size = PRM.Gadget_ss = Frame Stack Size of the API having JOP Gadget ("jmp [rbx]")
    add rsp, [rbx + 32]             ; Stack size = PRM.BTIT_ss = BaseThreadInitThunk Stack Size
    add rsp, [rbx + 56]             ; Stack size = PRM.RUTS_ss = RtlUserThreadStart Stack Size

    mov rbx, [rcx + 16]             ; Restoring original rbx (PRM.rbx)
    mov rdi, [rcx + 24]             ; ReStoring original rdi (PRM.rdi)
    mov rsi, [rcx + 88]             ; ReStoring original rsi (PRM.rsi)
    mov r12, [rcx + 96]             ; ReStoring original r12 (PRM.r12)
    mov r13, [rcx + 104]            ; ReStoring original r13 (PRM.r13)
    mov r14, [rcx + 112]            ; ReStoring original r14 (PRM.r14)
    mov r15, [rcx + 120]            ; ReStoring original r15 (PRM.r15)
    jmp qword [rcx + 8]             ; jmp to original return addr of called API Function (PRM.OG_retaddr) => addr. of PRM struct + 8 offset = PRM.OG_retaddr

section .data
; Define your data if any
