; Compile with
;  nasm -f elf32 -o <name>.o <name>.asm

global foo
global bar

section .bss
quux: resb 4
quuux: resb 4
quuuux: resb 4

section .text
foo:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov [quux], eax

    mov ebx, [ebp + 12]
    mov [quuux], ebx

    add eax, ebx
    mov [quuuux], eax

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