; Compile with
;  nasm -f elf32 -o <name>.o <name>.asm

global func

section .text
func:
    push ebp
    mov ebp, esp
    
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    and eax, 1
    cmp eax, 0
    jne .exit 

    mov eax, ebx

.exit:
    mov	esp, ebp
    pop ebp
    ret