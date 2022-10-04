; Compile with
;  nasm -f elf32 -o <name>.o <name>.asm

global func

section .text
func:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    add eax, ebx

    mov	esp, ebp
    pop ebp
    ret