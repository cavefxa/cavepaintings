---
title: "Cosmic Go"
date: 2025-04-11
author: "cavefxa"
category: "rev"
summary: "Challenge from TDCNET-CTF 25 - Download the challenge files: [cosmic_go.zip](/chall_files/cosmic_go/handout.zip)"
---

### Challenge Description
We've found an alien probe accessing our internal games system. We've extracted the agent, but we're not sure what it's doing, it seems to be written in some ancient alien language 

Note: Remote is not needed \
Hint: If you're trying to look into the PRNG, you're doing it wrong

### The Idea
I was watching YouTube and stumbled across a video about using chess ([Storing Files in Chess Games for Free Cloud Storage](https://www.youtube.com/watch?v=TUtafoC4-7k&pp=ygUWc3RvcmluZyBkYXRhIGluIGNoZXNzIA%3D%3D "Storing Files in Chess Games for Free Cloud Storage")) for file storage. Curious, I thought about other board games that could be used to store data. The YouTube video referenced the paper `Chess Games as a Method for File Encryption and Storage`, so naturally, I read it. I immediately wondered: "Can you hide more or less information in Go?" My intuition was that it would surely be more information, as the board is over twice as big! Then the epiphany came, I could write the challenge about Go, in the programming language Go - and I thought that was funny.

##### Algorithm 1
The algorithm for storing data is the crucial part. Let's consider a few ideas to get warmed up! First, the simple solution would be to use a tiny data matrix. If you're unfamiliar with the term data matrix, think about a QR code. We can use tiny data matrices; for example, a micro QR code can be as small as `11x11`. A `17x17` micro QR code can encode roughly `13` bytes of data. Given a tiny PNG of `11,797` bytes, you'd have to play `ceil(11797 / 13) = 907` Go games to encode an image, given you could reconstruct the QR code. Yikes, that's a lot of games. Let's think a little more.

##### Algorithm 2
Another approach could be to map rows or columns to specific binary representations. Playing on the first row could encode the binary data `0000`. Playing on the second row could encode `0001`. Playing on the third row could encode `0010`, and so on. This gives us `2^4 = 16` different encodings for `16` of the rows. We're left with 3 rows that we'd like to utilize to maximize the board's potential. A naive solution would be to simply cycle the rows, such that after `2` moves, `0000` would be represented by row `2`; after 3 moves, `0000` would be represented by row `3`; and then cycling back to row `1` (1-indexed) when exceeding `19`.

* This is what the Go binary is doing!

### Solution 
We can use this knowledge, along with the notion that the `games.db` file contains the data - to extract the flag.

```python
#!/usr/bin/env python3
import sqlite3
import json

con = sqlite3.connect("games.db")
games = con.cursor().execute("SELECT * FROM games ORDER BY id").fetchall()

row_to_bin = {i: f"{i:04b}" for i in range(16)}

out = bytearray()

for game_str in games:
    moves = json.loads(game_str[2])
    modifier = 0

    for i in range(0, len(moves)-1, 2):
        y1, y2 = moves[i]["y"], moves[i+1]["y"]
        bin1 = row_to_bin.get((y1 - modifier) % 19)
        bin2 = row_to_bin.get((y2 - modifier) % 19)

        out.append(int(bin1 + bin2, 2))
        modifier = (modifier + 1) % 19

with open("flag.bin", "wb") as f:
    f.write(out)
```

The flag is an image of `cowsay`, the ASCII cow, saying `TDCNET{go_is_4_h4rd3r_dr1v3}`

### Who reigns supreme - Go or Chess?
Storing an infinite amount of data in a single chess game is trivial, at least using USCF or standard over-the-board rules, which state that "*a player may claim a draw due to threefold repetition*" and also that "*the game is not automatically drawn if a position occurs for the third time*". So just because online sites automatically draw in such situations doesn't make that universal reality (or so one could argue). Consider the binary string 0101: encode 0s by Na3 and Na7, encode 1s by Nh3 and Nh7, and reset by moving back to the starting position. The sequence would be: `1. Na3 Nh6 2. Nb1 Ng8 3. Na3 Nh6 4. Nb1 Ng8`. Of course, this doesn't obfuscate data very effectively. I have no idea how to store an infinite amount of data in Go, so for now - Chess is the better hard drive!
