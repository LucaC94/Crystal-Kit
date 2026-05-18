[BITS 64]

    draugr_stub:
        pop rax                  ; Real return address in rax

        mov r10, rdi             ; Store OG rdi in r10
        mov r11, rsi             ; Store OG rsi in r11

        mov rdi, [ rsp + 32 ]    ; Storing struct in rdi
        mov rsi, [ rsp + 40 ]    ; Storing function to call

        ; ---------------------------------------------------------------------
        ; Storing our original registers
        ; ---------------------------------------------------------------------

        mov [ rdi + 24 ], r10     ; Storing OG rdi into param
        mov [ rdi + 88 ], r11     ; Storing OG rsi into param
        mov [ rdi + 96 ], r12     ; Storing OG r12 into param
        mov [ rdi + 104 ], r13    ; Storing OG r13 into param
        mov [ rdi + 112 ], r14    ; Storing OG r14 into param
        mov [ rdi + 120 ], r15    ; Storing OG r15 into param

        mov r12, rax              ; OG code used r12 for ret addr

        ; ---------------------------------------------------------------------
        ; Prepping to move stack args
        ; ---------------------------------------------------------------------

        xor r11, r11               ; r11 will hold the # of args that have been "pushed"
        mov r13, [ rsp + 0x30 ]    ; r13 will hold the # of args total that will be pushed

        mov r14, 0x200             ; r14 will hold the offset we need to push stuff
        add r14, 8
        add r14, [ rdi + 56 ]      ; stack size of RUTS
        add r14, [ rdi + 48 ]      ; stack size of BTIT
        add r14, [ rdi + 32 ]      ; stack size of our gadget frame
        sub r14, 0x20              ; first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time

        mov r10, rsp            
        add r10, 0x30              ; offset of stack arg added to rsp

        looping:
            xor r15, r15      ; r15 will hold the offset + rsp base
            cmp r11d, r13d    ; comparing # of stack args added vs # of stack args we need to add
            je finish
        
            ; ---------------------------------------------------------------------
            ; Getting location to move the stack arg to
            ; ---------------------------------------------------------------------
            
            sub r14, 8      ; 1 arg means r11 is 0, r14 already 0x28 offset.
            mov r15, rsp    ; get current stack base
            sub r15, r14    ; subtract offset
            
            ; ---------------------------------------------------------------------
            ; Procuring the stack arg
            ; ---------------------------------------------------------------------
            
            add r10, 8

            push qword [ r10 ]
            pop qword [ r15 ]   

            ; ---------------------------------------------------------------------
            ; Increment the counter and loop back in case we need more args
            ; ---------------------------------------------------------------------
            add r11, 1
            jmp looping
            
        finish:

        ; ----------------------------------------------------------------------
        ; Creating a big 320 byte working space
        ; ----------------------------------------------------------------------

        sub rsp, 0x200

        ; ----------------------------------------------------------------------
        ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart.
        ; Need to figure out why this cuts off the call stack
        ; ----------------------------------------------------------------------

        push 0

        ; ----------------------------------------------------------------------
        ; RtlUserThreadStart + 0x14  frame
        ; ----------------------------------------------------------------------
        
        sub rsp, [ rdi + 56 ]
        mov r11, [ rdi + 64 ]
        mov [ rsp ], r11
                
        ; ----------------------------------------------------------------------
        ; BaseThreadInitThunk + 0x21  frame
        ; ----------------------------------------------------------------------

        sub rsp, [ rdi + 32 ]
        mov r11, [ rdi + 40 ]
        mov [ rsp ], r11

        ; ----------------------------------------------------------------------
        ; Gadget frame
        ; ----------------------------------------------------------------------
        
        sub rsp, [ rdi + 48 ]
        mov r11, [ rdi + 80 ]
        mov [ rsp ], r11

        ; ----------------------------------------------------------------------
        ; Adjusting the param struct for the fixup
        ; ----------------------------------------------------------------------

        mov r11, rsi              ; r11 = function to call (rsi still holds it from top)

        mov [ rdi + 8 ], r12      ; struct.OriginalReturnAddress = real return address
        mov [ rdi + 16 ], rbx     ; struct.Rbx = original rbx (will be overwritten below)

        lea rax, [ rel fixup ]
        mov [ rdi ], rax          ; struct.Fixup = address of fixup label

        ; RBX always points to the struct so fixup can recover it regardless of which
        ; register the gadget uses.  gadget_reg = struct_ptr - GadgetOffset so that
        ; [gadget_reg + GadgetOffset] = [struct_ptr + 0] = struct.Fixup.
        mov rbx, rdi

        movsxd r13, DWORD [ rdi + 132 ]   ; r13 = GadgetOffset (signed 32->64)
        mov r14, rdi
        sub r14, r13                        ; r14 = struct_ptr - GadgetOffset

        ; ----------------------------------------------------------------------
        ; Syscall stuff. Shouldn't affect performance even if a syscall isnt made
        ; ----------------------------------------------------------------------
        mov r10, rcx
        mov rax, [ rdi + 72 ]

        ; ----------------------------------------------------------------------
        ; Set the gadget register.  RBX (enum 0) is already struct_ptr (offset
        ; must be 0 for RBX gadgets, enforced by find_gadget_info).  All other
        ; callee-saved registers are set to struct_ptr - GadgetOffset.
        ; After this block rdi may be clobbered, so all struct reads are done.
        ; ----------------------------------------------------------------------
        mov r15d, DWORD [ rdi + 128 ]      ; GadgetReg enum value

        cmp r15d, 0                          ; GADGET_REG_RBX – already done
        je gr_done

        cmp r15d, 1                          ; GADGET_REG_RDI
        jne gr_not_rdi
        mov rdi, r14
        jmp gr_done
        gr_not_rdi:

        cmp r15d, 2                          ; GADGET_REG_RSI
        jne gr_not_rsi
        mov rsi, r14
        jmp gr_done
        gr_not_rsi:

        cmp r15d, 3                          ; GADGET_REG_R12
        jne gr_not_r12
        mov r12, r14
        jmp gr_done
        gr_not_r12:

        cmp r15d, 4                          ; GADGET_REG_R13
        jne gr_not_r13
        mov r13, r14
        jmp gr_done
        gr_not_r13:

        cmp r15d, 5                          ; GADGET_REG_R14 (r14 already = value)
        jne gr_not_r14
        jmp gr_done
        gr_not_r14:

        mov r15, r14                         ; GADGET_REG_R15

        gr_done:
        jmp r11

        fixup:
            mov rcx, rbx
            add rsp, 0x200           ; Big frame thing
            add rsp, [ rbx + 48 ]    ; Stack size
            add rsp, [ rbx + 32 ]    ; Stack size
            add rsp, [ rbx + 56 ]    ; Stack size

            mov rbx, [ rcx + 16 ]     ; Restoring OG RBX
            mov rdi, [ rcx + 24 ]     ; ReStoring OG rdi
            mov rsi, [ rcx + 88 ]     ; ReStoring OG rsi
            mov r12, [ rcx + 96 ]     ; ReStoring OG r12
            mov r13, [ rcx + 104 ]    ; ReStoring OG r13 
            mov r14, [ rcx + 112 ]    ; ReStoring OG r14
            mov r15, [ rcx + 120 ]    ; ReStoring OG r15 
            push rax

            xor rax, rax 
            pop rax
            jmp QWORD [ rcx + 8 ]
