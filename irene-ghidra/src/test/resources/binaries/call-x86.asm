; Compile with
;  nasm -f elf32 -o <name>.o <name>.asm

global foo
global bar

section .text
foo:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    add eax, ebx

    mov	esp, ebp
    pop ebp
    ret

    ; Ghidra won't recognize bar as a separate function
    ; without a bit of padding before
    nop
    nop

bar:
    push 1
    push 2
    call foo
    ret