---
title: "Symbolic Execution with Angr: pt. 2 Usage Introduction"
date: 2021-09-29T13:04:00+02:00
---

# Simple usage 
```python
import angr
import claripy
```

When you're playing with angr, inevitably at the beginning you'll have to load a binary of some form, you can do this the following way:
```python
project_name = angr.Project("./<binary_name>")
```

Now angr works by using a lot of states which it steps through and investigates. To load our initial state we use the following command:
```python
state = proj.factory.entry_state()
```

There are a few ways to load binaries, as one would imagine. We can add these as arguments to the state. 
```python
# To start execution from specific address (reduce runtime)
state = proj.factory.entry_state(addr=0xdeadbeef)

# Specify which architecture to use
state = proj.factory.entry_state(arch="amd64")

# Specify what to send with stdin
state = proj.factory.entry_state(stdin="test_stdin_string\n")

# How to send data with argv
state = proj.factory.entry_state(args=["./<binary_name>", argv1])

# Use unicorn engine! This is often a good way to go about
state = proj.factory.entry_state(add_options=angr.options.unicorn)
```

To actually change the state, or use it in anyway, a simulation manager is needed:
```python
simgr = project_name.factory.simulation_manager(state)
```

Now to ACTUALLY change the state ( :D ), you need to use the simgr. You can do a few things:
```python
# Step one instruction at a time
simgr.step()

# Find specific address, avoid another
simgr.explore(find=0xdeadbabe, avoid=0xcafebeef)
```

# Solving and bitvectors
Python integers don't have the same semantics as words on a CPU, e.g. wrapping on overflow, so we work with bitvectors.

.BVV = concrete BIT VECTOR VALUE

.BVS = BIT VALUE SYMBOLIC

```python
db = state.solver.BVV(0xdeadbeef, 64) # Bitvector which angr uses 
state.solver.eval(db) # Python int representative of said bit vector
```

```python
# Solving equation for an integer
x = state.solver.BVS("x", 64)

state.solver.add(x > 4)
state.solver.add(x <= 5)
print(f"\n[+] Trying to solve for x, satisfiable? {state.satisfiable()}\nAnswer is {state.solver.eval(x)}")
```

```python
# Solving for a character (one byte)
n = state.solver.BVS("n", 8)

state.solver.add(n >= 0x41)
state.solver.add(n < 0x7f)
state.solver.add(n ^ 0x10 == 0x76)
solution = state.solver.eval(n)
print(f"\n[+] Trying to find the character that xored with 10 is 0x76.\nFound: {hex(solution)}")
```

# Flag?
Using angr for CTF style challenges, a bit of reverse engineering knowledge is a must. For example you can try to find out the length of the flag, and use this, to setup a symbolic bit vector array of flag characters. Imagine the following pseudocode:
```c
int flag(){
    if (strlen(flag) != 25)
        {
            return -1;
        }
    else
        {
        ...
        win();
        }
}
```

We know that the flag is 25 bytes. So we can set this as a constraint:
```python
flag_chars = [claripy.BVS("flag_%d" % i, 8) for i in range(25)]
flag = claripy.Concat(*flag_chars)
```

Firstly we make the array of flag_chars, we set each flag_%d to have a size of 8 bits, which is a byte, which is a character. We can use this as an input to stdin in state: 
```python
_state(stdin=flag)
```

Now running we can explore for a success string:
```python
simgr.explore(find=lambda s: b"Success string" in s.posix.dumps(1))
if "found" in str(simgr):
    s = simgr.found[0]
    print(s.posix.dumps(0)) #Flag
    print(s.posix.dumps(1)) #Input
```

Assuming we know that the flag's last character is "q" we can also set this as a constraint:
```python
state.solver.add(flag_chars[24] == ord("q"))
```

# Appendix - Further reading
[¹] - Cheatsheet: https://github.com/bordig-f/angr-strategies/blob/master/angr_strategies.md<br>

[²] - Constraint Solving and Symbolic Execution: https://flagbot.ch/lesson5.pdf<br>

[³] - Documentation: https://angr.io/<br>

[⁴] - Video by John Hammond: https://www.youtube.com/watch?v=RCgEIBfnTEI<br>
