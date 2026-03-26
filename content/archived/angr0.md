---
title: "Symbolic Execution with Angr: pt. 1 Theoretical Introduction"
date: 2021-09-29T12:09:45+02:00
---

# What is symbolic execution?
One might relate it to symbolic equations from mathematics in school. A few examples of symbolic equations might be:

```
a²+b²=c²
E=hf
F=ma
```

These are examples of symbolic equations. Values are defined based on symbols we call different things. For the symbols we could define constraints, eg. "f" must be larger than 0. or "a" is equal to 9.82 N/kg. Thus minimizing the amount of results or outcomes.
<br>
<br>
In computer science symbolic execution instead is a way of analyzing a program to see which inputs causes which execution branches to be run. Instead of using actual inputs, however, we use an interpreter which assumes symbolic values. 

# Example (stolen from wikipedia)

Example code:
```c
int f() {
  ...
  y = read();
  z = y * 2;
  if (z == 12) {
    fail();
  } else {
    printf("OK");
  }
}
```

Concrete:<br>
Upon executing the example code with a concrete input. The read() call on line 3, would read a concrete value, eg. `5`. It would then run the program throughout with that value. Z would be set to 10, and "OK" would be printed. We would now not know how fail would be called. Which we for explanation's sake want.


Symbolic:<br>
Executing with symbolic input. The read() would read a symbolic value eg. `µ` the program would then continue execution with this value, z would now be able to be any value, as we did not define a value for µ. When it reaches the `if (z==12)`, it can just say "sure! z is 12 lol", and forks this as a new process with the other else statement. If a program is large enough, this becomes infeasible, because there'll be too many paths - this is called a path explosion.


# What is angr (stolen from documentation)

Angr is a python framework for analyzing binaries. It can do automatic ROP-chaining, binary hardening, automatic exploit generation, and finally but probably most known for, it's symbolic execution. 

Angr recommends installing in a virtual environment as follows:
```
mkvirtualenv angr
pip install angr
```
or using the provided docker container.

I for one, however just installed it "normally", using pip.
```
pip3 install angr
```
