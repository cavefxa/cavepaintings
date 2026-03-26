---
title: "Roll"
date: 2023-09-17
author: "cavefxa"
category: "crypto"
summary: "Challenge from TDCNET-CTF 23 - Download the challenge files: [roll.zip](/chall_files/roll/handout.zip)"
---

### Challenge Description
Hans Peter walks his dog, phew - what a commitment! He is going to play some D&D with his friends later, phew - what a commitment!

### Solution
I made a `custom` commitment scheme for this challenge. I tried to hint subtly in the description, that the challenge is related to the Pedersen commitment scheme. 

A commitment scheme is a cryptographic primitive that allows one to commit to a chosen value (or chosen statement) while keeping it hidden to others, while maintaining the ability to reveal the committed value later. 

This can be very useful for online casinos, for example: Natalie wants to play online roulette, she puts in the money, and clicks play. After the play button was pressed, she received a commitment from the casino, and the roulette table begins to spin - she loses, and the value is revealed - showing that she was not being tricked. 

The specifically suspicious thing about this code is the `verify()` function:
```python
def verify(param, c, r, x):
    q, g, h = param
    return pow(c, (q-1)//2, q) == pow((pow(g,x,q) * pow(h,r,q) % q), (q-1)//2, q)
```

We're using Legendre's Symbol to check if both of the parameters are quadratic residues. We take a quick look at the numbers being given to `verify`:

```python
if verify(keygen, c, r, secret_roll) == verify(keygen, c, r, your_roll):
```

We see that the first part is:

```python
pow(c, (q-1)//2, q)
```

And we already know `c`. This is generated as such:

```python
c,r = commit(keygen, secret_roll)
print(f"Here's my commitment, so you'll trust me!")
print(f"{c = }")
```

We have 6 possible options here for the commitment:

```
commit(keygen, 1)
commit(keygen, 2)
commit(keygen, 3)
...
commit(keygen, 6)
```

Let's go back to the following code:

```python
pow(c, (q-1)//2, q)
```

Whenever `c` is a quadratic residue, the result of the above calculation will always yield a quadratic residue. What if all the rolls are quadratic residues?

Below is a crude solve script:
```python
while True:
    q, g, h = get_q(), get_g(), get_h()
    param = q, g, h
    commit_qr = pow(get_com(), (q-1)//2, q)
    
    # Check if all commitments equal 1 when raised to (q-1)//2
    if all(pow(commit(param, i)[0], (q-1)//2, q) == 1 for i in range(1, 7)):
        io.sendline(b"Y" if commit_qr == 1 else b"G")
    else:
        io.sendline(b"G")

io.interactive()
```

And then we get the flag:
`TDCNET{th3y_s33_me_r0ll1n_th3Y_h4t!nG}`
