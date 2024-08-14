[bits 64]

default rel

; export the function
global SyscallIndirect
global SyscallDirect

[section .text$B]
    ; perform indirect syscalls
    SyscallIndirect:
        mov r15, 1
        jmp Start
    ret

    ; perform direct syscalls
    SyscallDirect:
        mov r15, 2
        jmp Start
    ret

    ; init some registers
    Start:
        mov r10, gs:[60h]            ; peb
        mov r11d, dword [r10 + 0xE8] ; peb->NumberOfHeaps, used as a counter
        mov r12, [r10 + 0xF0]        ; peb->ProcessHeaps

    ; loop through the heaps to find our global instance
    FindInstance:
        mov r13, [r12]  ; get the address of the heap/instance struct
        mov r14d, [r13] ; get the first 4 bytes of structure -> context

        ; check if it is our context structure
        ; if so, exec the syscall
        cmp r14d, 0xc0debabe
        je SyscallExec

        ; decrement the counter
        dec r11

        ; increment the heap table pointer
        add r12, 0x08

        ; check we went through all heaps
        cmp r11, 0
        jne FindInstance

        ; went through all heaps and did not find the context structure, return STATUS_INTERNAL_ERROR
        mov rax, 0xC000000D
    ret

    ; execute the syscall now that we got its data
    SyscallExec:
        ; pointer to the syscall structure
        ; + 0x8 because the context structure is padded with 4 bytes to preserve alignment
        mov r14, [r13 + 0x8]

        ; prepare the syscall
        mov r10, rcx
        mov eax, [r14 + 8]

        ; perform indirect syscalls
        cmp r15, 1
        je SyscallExecIndirect

        ; perform direct syscalls
        cmp r15, 2
        je SyscallExecDirect

        ; unknow r15 value return error
        mov rax, 0xC000000D
    ret

    SyscallExecIndirect:
        ; r14 contains the base address of the syscall
        ; not the address of the syscall instructions
        ; the syscall instruction is always 0x12 after the base address
        ; jump to it
        mov r14, [r14]
        add r14, 0x12
        jmp QWORD r14
    ret

    SyscallExecDirect:
        syscall
    ret
