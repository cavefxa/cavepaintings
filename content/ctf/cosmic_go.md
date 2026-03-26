---
title: "Event Horizon"
date: 2025-04-10
author: "cavefxa"
category: "rev"
summary: "Challenge from TDCNET-CTF 25 - Download the challenge files: [event_horizon.zip](/chall_files/event_horizon/handout.zip)"
---

### Challenge Description
There was a bunch of issues with radiation, when we were trying to figure out the event horizon of this black hole. It worked on our test data! Can you figure out what's wrong?

### The Idea
I wanted to have some sort of geometric algorithm, that would require some level of "plotting" or intuition of the geometrics, before you could get the flag. The shape I wanted to play with was the `convex hull`, i.e. *"the smallest set of convex nodes that contain a shape"*. Here the event horizon of a black hole.

Initially I tried to make the algorithm inefficient. I tried using `Quickhull`, which degenerates to `O(n^2)` in the worst case, but the binary would get too big. Eventually I decided to make `bogohull`, a brain child of `bogosort`, and `convexhull`. Utilizing the stupidity of `bogosort`, to make the convex hull algorithm run forever. To those uninitiated, `bogohull` is *"An algorithm which successively generates permutations of its input until it finds one that is sorted"*, i.e. generate random numbers, check if it is a solution, otherwise continue.

### Solution 
We can reverse the binary, and we'll figure out what was stated above. Extracting the points we can plot it. From the reverse engineering part, we see that the flag characters are encoded as lengths between vertices in the hull. 

```python
import numpy as np
from scipy.spatial import ConvexHull
import math
import random

coords_raw = [
    # ...
    (242.37, 500.07), (253.5, 476.07),
    (2.96, 524.66), (275.16, 509.44), (274.58, 500.07),
    (285.11, 494.22), (294.48, 492.46),
    (3.44, 491.88), (271.65, 529.93) 
]

points = np.array(coords_raw)
hull = ConvexHull(points)

ascii_message = ''
for i in range(len(hull.vertices)):
    idx1 = hull.vertices[i]
    idx2 = hull.vertices[(i + 1) % len(hull.vertices)]
    
    x0, y0 = points[idx1]
    x1, y1 = points[idx2]
    dist = math.hypot(x1 - x0, y1 - y0)
    
    code = round(dist)
    if 32 <= code <= 126:
        ascii_message += chr(code)

print(ascii_message)
```

This gives the output `x3VN0c{TENCDT}`. This looks like a flag, because it contains the data.
It is all about which way to read it, this is quite obvious from looking at it, but the reason is, 
that you're going clockwise around the convex hull, with one letter at a time. Giving:
`TDCNET{c0NV3x}`
