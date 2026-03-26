---
title: "Little Alien Computer"
date: 2025-04-16
author: "cavefxa"
category: "pwn"
summary: "Challenge from TDCNET-CTF 25 - Download the challenge files: [vmbs.zip](/chall_files/vmbs/handout.zip)"
---

### Challenge Description
You were given a computer salvaged from an Arachnid hive ship. The interface is ancient. Something within it seems to be a custom language. This is your first job as an intern with the military intelligence, don't disappoint your big boss Carl Jenkins!!

### Easter Egg
Running strings on the file reveal `(c) 2093 Stu. Alien Madnick, Inc. All Rights Reserved`.
Searching the internet for Stu Madnick, we get a reference to Stuart Madnick, who `developed the little man computer model that is still widely used to introduce computer architecture concepts,`. The Little Alien Computer is heavily inspired by this architecture. 

### Solution
Reversing the VM implementation, with (or without) the intel gathered from the easter-egg, we'll quickly find that there are no bounds checking. The flag is conveniently placed after our "bucket", or memory where we can store and read variables. We can index out of bounds to read a character at a time. 

We write a payload:
```
INP 1      // Input the value 1 and store it in the accumulator
STA 1      // Store the value 1 from accumulator into memory location 1 (arr[1] = 1)

INP 94     // Input the value 94 and store it in the accumulator  
STA 0      // Store 94 into memory location 0 (arr[0] = 94)

INP 0      // Input the value 0 into the accumulator
LOAD       // Load from memory address stored in accumulator (load from address 0)
           // This loads the value 94 (from arr[0]) into the accumulator

ADD 1      // Add the value from memory location 1 to accumulator (94 + 1 = 95)
STA 0      // Store the result back into memory location 0 (arr[0] = 95)

LOAD       // Load from memory address stored in accumulator 
           // Now loads from address 95 (reading out-of-bounds memory)

OUT        // Output the character at that memory location
BRZ 999    // If accumulator is zero, branch to instruction 999 (exit condition)
BRA 9      // Otherwise, branch back to instruction 9 (the ADD 1 line)
```

We can create a Python script to map opcodes understood by the Little Alien Computer:
```python
from pwn import *

opcode_table = { "ADD": "A", "SUB": "S", "STA": "T", 
                "LOAD": "L", "BRA": "B", "BRZ": "Z", 
                "INP": "I", "OUT": "O", "NOP": "X", }

payload = "..." # see above

v = ""
for token in payload.split():
    try:
        v += opcode_table[token]
    except:
        v += token 

v += "#"

print(v) 

# prints: I1T1I94T0I0LA1T0LOB9#
```

Running this in the VM gives:
`TDCNET{1m_d01nG_my_p4rT_M1LInt}`


The flag is a reference to the great movie "Starship Troopers", which is hinted at in the description.

### Source 
```assembly
org 0x7c00

start:
    xor di, di          

get_charloop:
    mov ah, 0x00        
    int 0x16            
    cmp al, '#'         
    je parse_lmc
    mov ah, 0x0e        
    int 0x10            
    mov [lmc_ram+di], al
    inc di
    cmp di, 24
    jne get_charloop

parse_lmc:
    mov si, [lmc_pc]
    mov al, [lmc_ram + si] 
    cmp si, 24             
    je end

    cmp al, 'A'
    je add_handler
    cmp al, 'S'
    je sub_handler
    cmp al, 'T'
    je sta_handler
    cmp al, 'L'
    je load_handler
    cmp al, 'B'
    je bra_handler
    cmp al, 'Z'
    je brz_handler
    cmp al, 'I'
    je input_handler
    cmp al, 'O'
    je output_handler

next_instruction:
    inc si
    mov [lmc_pc], si
    jmp parse_lmc

get_operand:
    xor bx, bx

    get_digit_loop:
        inc si
        mov al, [lmc_ram + si]

        cmp al, 0
        je get_operand_done

        cmp al, '0'
        jl get_operand_done
        cmp al, '9'
        jg get_operand_done

        sub al, '0'
        xor ah, ah
        add bx, ax
        jmp get_digit_loop
    get_operand_done:
        dec si
        ret

add_handler:
    call get_operand
    mov al, [lmc_storage + bx]
    add [lmc_acc], al
    jmp next_instruction

sub_handler:
    call get_operand
    mov al, [lmc_acc]
    sub [lmc_storage + bx], al
    jmp next_instruction

sta_handler:
    call get_operand
    mov al, [lmc_acc]
    mov [lmc_storage + bx], al
    jmp next_instruction

load_handler:
    mov bx, [lmc_acc]
    mov al, [lmc_storage + bx]
    mov [lmc_acc], al
    jmp next_instruction

bra_handler:
    call get_operand
    jmp update_branch

brz_handler:
    call get_operand
    mov al, [lmc_acc]
    cmp al, 0
    je update_branch

    jmp next_instruction

input_handler:
    call get_operand
    mov [lmc_acc], bx
    jmp next_instruction

output_handler:
    mov ah, 0x0e        
    mov ch, [lmc_acc]
    mov al, ch
    int 0x10

    jmp next_instruction

update_branch:
    mov [lmc_pc], bx
    jmp parse_lmc

no_work:
    mov ah, 0x0e        
    mov al, '^'
    int 0x10           

halt:
    cli
    hlt

end:
    jmp halt

lmc_ram:
times 25 db 0
lmc_storage:
times 10 db 0
lmc_pc:
dw 0
lmc_acc:
dw 0
flag:
db "TDCNET{1m_d01nG_my_p4rT_M1LInt}", 0
copyright:
db "(c) 2093 Stu. Alien Madnick, Inc. All Rights Reserved", 0
alien:
db "ATTENTION EARTHLING: This bootloader contains alien technology"
db "compact enough for interstellar travel. Our species fits entire"
db "quantum computers in 512 bytes.", 0

times 510-($-$$) db 0   ; Pad the rest of the sector with zeros
dw 0xAA55               ; Boot sector signature
```
