# Cryptography Knowledge Summary — Pwn.college
### Part 1: XOR · OTP · AES-ECB

---

## Table of Contents
1. [XOR Cipher](#1-xor-cipher)
2. [One-Time Pad (OTP)](#2-one-time-pad-otp)
3. [AES-ECB Mode](#3-aes-ecb-mode)
4. [AES-CBC Mode → Part 2](#)
5. [Summary & Cheat Sheet → Part 2](#)

---

## 1. XOR Cipher

### 1.1. Basics

**XOR (Exclusive OR)** is the fundamental bitwise operation in symmetric cryptography:

```
Truth Table:
A | B | A ⊕ B
--|---|------
0 | 0 |  0
0 | 1 |  1
1 | 0 |  1
1 | 1 |  0
```

**Key properties:**
| Property | Formula |
|---|---|
| Commutative | `A ⊕ B = B ⊕ A` |
| Associative | `(A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)` |
| Identity | `A ⊕ 0 = A` |
| Self-inverse | `A ⊕ A = 0` |
| Reversible | `A ⊕ B ⊕ B = A` |

### 1.2. Encrypt / Decrypt

```
Encrypt:  Plaintext  ⊕ Key = Ciphertext
Decrypt:  Ciphertext ⊕ Key = Plaintext   ← same operation!

Example:
Plaintext:  01010011 01100101 01100011   ("Sec")
Key:        00010001 00010001 00010001   (0x11 repeated)
          ⊕ ─────────────────────────
Ciphertext: 01000010 01110100 01110010   (0x42 0x74 0x72)
```

### 1.3. Code

```python
# Single-byte key
def xor_encrypt(plaintext: bytes, key: int) -> bytes:
    return bytes([p ^ key for p in plaintext])

def xor_decrypt(ciphertext: bytes, key: int) -> bytes:
    return bytes([c ^ key for c in ciphertext])   # identical to encrypt

# Multi-byte key stream
from Crypto.Util.strxor import strxor

def xor_stream(data: bytes, key: bytes) -> bytes:
    key_rep = (key * (len(data) // len(key) + 1))[:len(data)]
    return strxor(data, key_rep)
```

### 1.4. Known-Plaintext Attack

**Condition:** You know a plaintext–ciphertext pair → recover the key.

```
Given:   Plaintext ⊕ Key = Ciphertext
Derive:  Key = Plaintext ⊕ Ciphertext
```

**Example:** You know the ciphertext of `"sleep"`, and want to forge the ciphertext of `"flag!"`:

```python
from Crypto.Util.strxor import strxor

sleep_ct = bytes.fromhex("6286bb6ab5")
sleep_pt = b"sleep"

# Step 1: recover the key fragment
key = strxor(sleep_ct, sleep_pt)

# Step 2: forge with the new command
flag_ct = strxor(b"flag!", key)

# One-liner (skip key recovery):
# flag_ct = strxor(strxor(sleep_ct, sleep_pt), b"flag!")
# Because: C_new = P_new ⊕ K = P_new ⊕ C_old ⊕ P_old
```

---

## 2. One-Time Pad (OTP)

### 2.1. Theory

**OTP** = XOR with a key that is **truly random** and **as long as the plaintext**.

```
┌─────────────┐     ┌──────────────┐
│  Plaintext  │     │  Random Key  │
│  (n bytes)  │     │  (n bytes)   │
└──────┬──────┘     └──────┬───────┘
       └─────────⊕─────────┘
                 │
          ┌──────▼──────┐
          │ Ciphertext  │
          └─────────────┘
```

**Rules (break any one → completely broken):**
- ✅ Key must be **truly random** (not pseudo-random)
- ✅ Key must be **as long as** the plaintext
- ✅ Key must be used **only once**

### 2.2. Decryption

```python
key    = bytes.fromhex("7d29459b4f15aa95...")
cipher = bytes.fromhex("0d5e2bb52c7ac6f9...")

plaintext = bytes([c ^ k for c, k in zip(cipher, key)])
print(plaintext.decode())
```

### 2.3. Many-Time Pad Attack (Key Reuse)

**Vulnerability:** If the key is reused, XOR-ing two ciphertexts cancels the key:

```
C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2    (K cancels out!)
```

**Real exploit — Server encrypts flag with K, then lets you encrypt any input with the same K:**

```
┌─────────┐                              ┌──────────┐
│ Attacker│                              │  Server  │
└────┬────┘                              └────┬─────┘
     │  1. "Give me the encrypted flag"       │
     │ ──────────────────────────────────────>│
     │                                        │ Flag_CT = Flag ⊕ K
     │            Flag_CT (hex)               │
     │ <──────────────────────────────────────│
     │                                        │
     │  2. "Please encrypt this for me:"      │
     │     Send: Flag_CT  (as plaintext!)     │
     │ ──────────────────────────────────────>│
     │                                        │ Result = Flag_CT ⊕ K
     │                                        │        = (Flag ⊕ K) ⊕ K
     │                                        │        = Flag  ← 
     │            Result (hex)                │
     │ <──────────────────────────────────────│
     │                                        │
     │  3. bytes.fromhex(Result) = Flag!      │
```

**Why it works:**
```
Encrypt round 1:  Flag ⊕ K = Flag_CT
Encrypt round 2:  Flag_CT ⊕ K = (Flag ⊕ K) ⊕ K = Flag
                                  ↑ K cancels itself!
```

---

## 3. AES-ECB Mode

### 3.1. Theory

**AES-ECB** encrypts each 16-byte block **independently** with the same key:

```
  Block 0          Block 1          Block 2
┌──────────┐     ┌──────────┐     ┌──────────┐
│   P[0]   │     │   P[1]   │     │   P[2]   │
└────┬─────┘     └────┬─────┘     └────┬─────┘
     ▼                ▼                ▼
  AES(K)           AES(K)           AES(K)
     ▼                ▼                ▼
┌──────────┐     ┌──────────┐     ┌──────────┐
│   C[0]   │     │   C[1]   │     │   C[2]   │
└──────────┘     └──────────┘     └──────────┘

⚠️  Same plaintext block + same key → ALWAYS same ciphertext block!
```

**ECB Penguin Problem:**  
Pixels of the same color produce identical 16-byte plaintext blocks → identical ciphertext blocks → when rendered back, the image keeps its **shape** (only colors change). The pattern is fully visible.

### 3.2. Basic Encrypt/Decrypt

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)

# Encrypt
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(b"Secret message", AES.block_size))

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), AES.block_size)
```

### 3.3. Detect Block Size & ECB Mode

```python
def detect_block_size(encrypt_fn) -> int:
    """Increase input length until output jumps → that jump = block size."""
    prev = len(encrypt_fn(b""))
    for i in range(1, 64):
        curr = len(encrypt_fn(b"A" * i))
        if curr > prev:
            return curr - prev
    return -1

def is_ecb(encrypt_fn, block_size: int = 16) -> bool:
    """Send 3 identical blocks; if any two ciphertext blocks match → ECB."""
    ct = encrypt_fn(b"A" * block_size * 3)
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))
```

### 3.4. PKCS#7 Padding

```
Plaintext length mod 16 | Bytes added
------------------------|-----------------------------------
 0  (e.g. 16, 32 bytes) | \x10 * 16   ← FULL EXTRA BLOCK
 1  (e.g. 17 bytes)     | \x0f * 15
 2                      | \x0e * 14
 ...
13                      | \x03\x03\x03
14                      | \x02\x02
15                      | \x01
```

> **Critical:** PKCS#7 *always* appends padding — even when the plaintext is already 16 bytes.  
> Reason: a trailing `\x01` byte must unambiguously mean "padding", not data.

---

### 3.5. ECB Byte-at-a-time — Suffix Attack

**Scenario:** Server encrypts `YOUR_INPUT || SECRET_FLAG` with AES-ECB.

**Core idea:** Pad your input so exactly **1 unknown byte** lands at the end of a block → brute-force that byte by comparing ciphertext blocks.

---

#### Find `flag[0]` — Send 15 × "A"

```
Server encrypts:
┌──────────────────────────────────────────┐ ┌──────────────────────────┐
│  A  A  A  A  A  A  A  A  A  A  A  A  A  A  A │flag[0]│ flag[1] ... pad│
│                  Block 0 (16 bytes)      │ │       Block 1+           │
└──────────────────────────────────────────┘ └──────────────────────────┘
                                         ↑
                           1 unknown byte at end of Block 0

target = encrypt(b"A" * 15)[:16]   ← Block 0 = 15 A's + flag[0]
```

Brute-force:

```python
target = encrypt(b"A" * 15)[:16]

for ch in range(256):
    if encrypt(b"A" * 15 + bytes([ch]))[:16] == target:
        print(f"flag[0] = {chr(ch)!r}")   # e.g. 'p'
        break
```

---

#### Find `flag[1]` — Send 14 × "A"

```
┌──────────────────────────────────────────────────┐
│  A  A  A  A  A  A  A  A  A  A  A  A  A  A    │'p'│flag[1]│
│                    Block 0 (16 bytes)            │
└──────────────────────────────────────────────────┘
                                     ↑ known           ↑ brute-force

target = encrypt(b"A" * 14)[:16]

for ch in range(256):
    if encrypt(b"A" * 14 + b"p" + bytes([ch]))[:16] == target:
        print(f"flag[1] = {chr(ch)!r}")   # e.g. 'w'
        break
```

---

#### Find `flag[16]` — Move to Block 1

After recovering the first 16 bytes `flag[0:16]`, shift focus to **Block 1**:

```
Send 15 × "A":
┌─────────────────────────┐  ┌─────────────────────────────┐
│  A*15  +  flag[0]       │  │  flag[1:16]  +  flag[16]    │
│       Block 0           │  │         Block 1             │
└─────────────────────────┘  └─────────────────────────────┘
                                                  ↑ find this

target = encrypt(b"A" * 15)[16:32]   ← Block 1

for ch in range(256):
    guess = b"A" * 15 + known_so_far + bytes([ch])
    if encrypt(guess)[16:32] == target:
        ...
```

---

#### Why `pad_len = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)`?

```
i=0  → pad=15 → Block 0: [ A*15 | flag[0] ]          ← 1 unknown at end
i=1  → pad=14 → Block 0: [ A*14 | flag[0] | flag[1] ] ← 1 unknown at end
...
i=15 → pad=0  → Block 0: [ flag[0:15] | flag[15] ]   ← 1 unknown at end
i=16 → pad=15 → Block 1: [ flag[1:16] | flag[16] ]   ← move to Block 1
i=17 → pad=14 → Block 1: [ flag[2:16] | flag[17] ]
...
```

The unknown byte is always the *last* byte of the target block, no matter where we are in the flag.

---

#### Complete Code

```python
BLOCK_SIZE = 16

def get_block(data: bytes, n: int) -> bytes:
    """Return the n-th block (0-indexed)."""
    return data[n * BLOCK_SIZE : (n + 1) * BLOCK_SIZE]

def ecb_suffix_attack(encrypt_fn) -> bytes:
    """
    encrypt_fn(input) = AES-ECB(input || secret_flag)
    Returns the recovered secret_flag.
    """
    known = b""

    # 1. Find flag length
    base = len(encrypt_fn(b""))
    for i in range(1, BLOCK_SIZE + 1):
        if len(encrypt_fn(b"A" * i)) > base:
            flag_len = base - i
            break

    # 2. Recover one byte at a time
    for i in range(flag_len):
        pad_len      = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)
        target_block = i // BLOCK_SIZE

        target = get_block(encrypt_fn(b"A" * pad_len), target_block)

        for ch in range(256):
            guess = b"A" * pad_len + known + bytes([ch])
            if get_block(encrypt_fn(guess), target_block) == target:
                known += bytes([ch])
                break

    return known
```

---

### 3.6. ECB Byte-at-a-time — Prefix Attack

**Scenario:** Server encrypts `SECRET_FLAG || YOUR_INPUT` with AES-ECB.

**Why harder than suffix:** We cannot pad bytes *before* the flag, so we cannot directly slide one unknown byte to the end of a block.

**Strategy — Self-referencing block trick:**

```
Create an input so that the ciphertext contains two blocks with identical content:
  Block A (target):    flag[i] + FILLER * 15   ← built by the server
  Block B (reference): candidate + FILLER * 15  ← built by us

If candidate == flag[i]  →  Block A == Block B  →  their ciphertext blocks match!
(ECB property: same plaintext block → same ciphertext block)
```

**Alignment calculation:**

```
Flag = 25 bytes. We want to attack flag[24] (last byte).

(pos+1) = 25 → already a multiple of ... no, 25 % 16 = 9
align_pad = 16 - 9 = 7   (push flag[24] to end of Block 1)

Layout after alignment:
┌───── Block 0 ─────┐┌──────── Block 1 ────────┐┌────── Block 2 ──────┐
│ flag[0:16]         ││ flag[16:25] + 0x00 * 7   ││ candidate + 0x00*15  │
└────────────────────┘└──────────────────────────┘└─────────────────────┘
         ↑ fixed                   ↑ flag[24] here           ↑ reference

When candidate == flag[24]:  Block 1 ciphertext == Block 2 ciphertext ✓
```

```python
def ecb_prefix_attack(encrypt_fn, flag_len: int) -> bytes:
    """
    encrypt_fn(input) = AES-ECB(flag || input)
    Recover flag byte-by-byte from the end.
    """
    BS     = 16
    FILLER = 0x00
    known  = b""

    for pos in range(flag_len - 1, -1, -1):
        # Align: push flag[pos] to the end of its block
        remainder = (pos + 1) % BS
        align_pad = (BS - remainder) % BS

        # Target block index (contains flag[pos])
        target_block_idx = (pos + align_pad) // BS

        for candidate in range(256):
            # reference block = candidate + known + filler (padded to 16)
            ref_part = bytes([candidate]) + known
            filler   = bytes([FILLER]) * (BS - len(ref_part) % BS) \
                       if len(ref_part) % BS else b""
            inp = bytes([FILLER]) * align_pad + ref_part + filler
            ct  = encrypt_fn(inp)

            # Reference block index (in the ciphertext)
            ref_block_idx = (flag_len + align_pad) // BS

            if get_block(ct, target_block_idx) == get_block(ct, ref_block_idx):
                known = bytes([candidate]) + known
                break

    return known
```

> **Note:** Index calculations vary by challenge — always print the block layout first to verify before brute-forcing.
# Cryptography Knowledge Summary — Pwn.college
### Part 2: AES-CBC · Padding Oracle · Summary

---

## 4. AES-CBC Mode

### 4.1. Theory

**CBC (Cipher Block Chaining)** — each block is XOR-ed with the previous ciphertext block before encryption:

```
ENCRYPTION:
         IV               C[0]              C[1]
          │                 │                 │
    P[0]──⊕           P[1]──⊕           P[2]──⊕
          │                 │                 │
       AES-E(K)          AES-E(K)          AES-E(K)
          │                 │                 │
          ▼                 ▼                 ▼
         C[0]              C[1]              C[2]

DECRYPTION:
         C[0]              C[1]              C[2]
          │                 │                 │
       AES-D(K)          AES-D(K)          AES-D(K)
          │                 │                 │
          ▼                 ▼                 ▼
    IV───⊕            C[0]──⊕           C[1]──⊕
          │                 │                 │
          ▼                 ▼                 ▼
         P[0]              P[1]              P[2]
```

**Formulas:**
```
Encrypt:  C[i] = AES_E(K,  P[i] ⊕ C[i-1])    where C[-1] = IV
Decrypt:  P[i] = AES_D(K, C[i]) ⊕ C[i-1]     where C[-1] = IV
```

### 4.2. Basic Code

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)

# Encrypt — prepend auto-generated IV
cipher = AES.new(key, AES.MODE_CBC)
ct = cipher.iv + cipher.encrypt(pad(b"Secret message", AES.block_size))

# Decrypt — split IV from first 16 bytes
iv, body = ct[:16], ct[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(body), AES.block_size)
```

---

### 4.3. CBC Bit-Flipping Attack

**Principle:** `P[i] = AES_D(K, C[i]) ⊕ C[i-1]` — changing `C[i-1]` changes `P[i]` predictably.

```
Want to change  P[0]  from  "sleep"  to  "flag!":

IV_new = IV_old ⊕ pad("sleep") ⊕ pad("flag!")
              ↑ cancels old     ↑ injects new

When decrypted:
P'[0] = AES_D(K, C[0]) ⊕ IV_new
      = AES_D(K, C[0]) ⊕ IV_old ⊕ pad("sleep") ⊕ pad("flag!")
      =       pad("sleep")       ⊕ pad("sleep") ⊕ pad("flag!")
      = pad("flag!")  ✓
```

```python
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

msg    = bytes.fromhex("a28438ea5973164...")   # IV || CT
iv, ct = msg[:16], msg[16:]

pt_old = pad(b"sleep", 16)
pt_new = pad(b"flag!", 16)

iv_new = strxor(iv, strxor(pt_old, pt_new))
forged = iv_new + ct   # decrypts to "flag!" ✓
```

> **Side effect:** Bit-flipping corrupts `P[i-1]` (the block whose ciphertext we modified).  
> For the first block, we modify the IV — so no plaintext block is corrupted.

---

### 4.4. Padding Oracle Attack — Decrypt

#### 4.4.1. CBC Decryption Internals

```
             C[i]
              │
          AES_D(K)        ← depends only on C[i] and K
              │
        Intermediate[i]   ← THIS VALUE IS CONSTANT regardless of C[i-1]
              │
   C[i-1] ───⊕            ← we control this
              │
             P[i]

Key equations:
  I[i] = AES_D(K, C[i])      ← fixed for a given C[i]
  P[i] = I[i] ⊕ C[i-1]      ← change C[i-1] → change P[i] precisely
```

**Goal:** Find `I[i]` (16 bytes) → recover `P[i] = I[i] ⊕ C[i-1]_original`

#### 4.4.2. What Is the Oracle?

```python
def oracle(iv: bytes, ct_block: bytes) -> bool:
    """
    Server decrypts then checks PKCS#7 padding.
    Returns:
      True  if last bytes form valid padding: \x01, \x02\x02, ..., \x10*16
      False otherwise
    """
```

#### 4.4.3. Find `I[15]` — Step-by-Step with Real Numbers

```
Given:
  CT block = [E3 4F 19 A2 7B C0 55 D8 91 3E F7 60 AA 8D 44 B2]
  IV orig  = [31 41 59 26 53 58 97 93 23 84 62 64 33 83 27 95]

─── Step 1: Find I[15] ───────────────────────────────────────────────

Craft a fake IV: [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 XX]
Goal: P'[15] = I[15] ⊕ XX = 0x01  (1-byte valid PKCS#7)

Brute-force XX = 0x00 → 0xFF:
  XX = 0x00 → oracle: False
  XX = 0x01 → oracle: False
  ...
  XX = 0xD7 → oracle: True ✓

Therefore:
  I[15] = 0xD7 ⊕ 0x01 = 0xD6
  P[15] = I[15] ⊕ IV[15] = 0xD6 ⊕ 0x95 = 0x43 = 'C'
```

> ⚠️ **False positive:** `P'[14:16] = [0x02, 0x02]` is also valid padding!  
> **Verify:** flip `IV'[14]` — if oracle still returns True → confirmed `\x01`.  
> If oracle returns False → it was `\x02\x02`, keep searching.

#### 4.4.4. Find `I[14]`

```
─── Step 2: Find I[14] ───────────────────────────────────────────────

Known: I[15] = 0xD6
Goal: P'[14] = P'[15] = 0x02  (2-byte valid PKCS#7)

Fix  IV'[15] = I[15] ⊕ 0x02 = 0xD6 ⊕ 0x02 = 0xD4  ← forces P'[15] = 0x02
Vary IV'[14] = YY  (brute-force)

  YY = 0xA3 → oracle: True ✓

Therefore:
  I[14] = 0xA3 ⊕ 0x02 = 0xA1
  P[14] = I[14] ⊕ IV[14] = 0xA1 ⊕ 0x27 = 0x86
```

#### 4.4.5. General Pattern

```
To find I[16 - pad_val]  at step pad_val (1 → 16):

  IV'[j]           = I[j] ⊕ pad_val   for j > (16 - pad_val)   ← already known
  IV'[16 - pad_val] = XX               brute-force 0..255
  IV'[j]           = 0x00             for j < (16 - pad_val)   ← don't care

  oracle returns True → I[16 - pad_val] = XX ⊕ pad_val
```

#### 4.4.6. Code — Single Block

```python
def poa_decrypt_block(ct_block: bytes, prev_block: bytes, oracle_fn) -> bytes:
    """
    Decrypt one AES block using a padding oracle.
    prev_block = IV (first block) or previous ciphertext block.
    """
    I = [0] * 16

    for pad_val in range(1, 17):
        pos = 16 - pad_val

        # Fix bytes to the right of current position
        fake_iv = [0] * 16
        for j in range(pos + 1, 16):
            fake_iv[j] = I[j] ^ pad_val

        # Brute-force current byte
        for candidate in range(256):
            fake_iv[pos] = candidate
            if oracle_fn(bytes(fake_iv), ct_block):

                # Verify last byte to rule out false positives
                if pad_val == 1 and pos > 0:
                    check = fake_iv.copy()
                    check[pos - 1] ^= 0xFF
                    if not oracle_fn(bytes(check), ct_block):
                        continue   # was a false positive

                I[pos] = candidate ^ pad_val
                break

    # Plaintext = Intermediate ⊕ previous block
    return bytes(i ^ p for i, p in zip(I, prev_block))
```

#### 4.4.7. Multi-Block Decrypt

```
Input:  IV || C[0] || C[1] || C[2]

P[0] = decrypt_block(C[0], IV)      prev = IV
P[1] = decrypt_block(C[1], C[0])   prev = C[0]
P[2] = decrypt_block(C[2], C[1])   prev = C[1]

Plaintext = P[0] || P[1] || P[2],  then strip PKCS#7
```

```python
def poa_decrypt(full_ct: bytes, oracle_fn) -> bytes:
    BS = 16
    iv, ct = full_ct[:BS], full_ct[BS:]
    blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]

    plaintext = b""
    prev = iv
    for block in blocks:
        plaintext += poa_decrypt_block(block, prev, oracle_fn)
        prev = block

    pad_len = plaintext[-1]
    return plaintext[:-pad_len]
```

---

### 4.5. Padding Oracle — Encrypt (Forgery)

**Goal:** Produce a valid ciphertext that decrypts to **any plaintext we want**, *without knowing the key.*

---

#### Why Is This Possible?

```
CBC Decrypt:

  C[i] ──► AES_D(K) ──► Intermediate[i] ──⊕── C[i-1] ──► P[i]
                              │
                  Fixed for a given C[i].
                  Does NOT depend on C[i-1].

Therefore:
  P[i]    = I[i] ⊕ C[i-1]
  C[i-1]  = I[i] ⊕ P[i]     ← rearranged!

If we can find I[i] (via POA) and we freely choose P[i],
we can compute the exact C[i-1] that produces that plaintext.
No key required!
```

---

#### Concrete Example — Encrypting `"ATTACK AT DAWN!!"`

**Target:** `b"ATTACK AT DAWN!!"` (16 bytes = 1 block)

After PKCS#7 padding (16 bytes → add full extra block):
```
PT[0] = b"ATTACK AT DAWN!!"       (our message)
PT[1] = b"\x10" * 16              (PKCS#7 block: 16 × 0x10)
```

We need to forge: `IV*  ||  C*[0]  ||  C*[1]`

---

**Step 1 — Pick a random last block**

```
C*[1] = os.urandom(16)
      = [A3 F2 11 CC 7E 05 B9 44 60 D1 82 3F AA 91 5C 2B]
        (any random bytes — doesn't matter)
```

---

**Step 2 — Find Intermediate[1] via POA**

Run the padding oracle on `C*[1]` (use arbitrary fake IV, brute-force all 16 bytes):

```
After ~4096 oracle calls:
  I[1] = AES_D(K, C*[1]) = [5D 3A 8F 01 C4 B7 22 9E 44 FF 10 63 D5 8C 77 E0]
```

---

**Step 3 — Compute C*[0]**

We want `P[1] = PT[1] = \x10 × 16`:

```
C*[0] = I[1] ⊕ PT[1]

byte by byte:
  I[1][0]  ⊕ 0x10 = 0x5D ⊕ 0x10 = 0x4D
  I[1][1]  ⊕ 0x10 = 0x3A ⊕ 0x10 = 0x2A
  I[1][2]  ⊕ 0x10 = 0x8F ⊕ 0x10 = 0x9F
  ...
  I[1][15] ⊕ 0x10 = 0xE0 ⊕ 0x10 = 0xF0

C*[0] = [4D 2A 9F 11 D4 A7 32 8E 54 EF 00 73 C5 9C 67 F0]
```

Now `C*[1]` decrypts to `PT[1]` when preceded by `C*[0]`. ✓

---

**Step 4 — Find Intermediate[0] via POA**

Run the oracle again, this time on `C*[0]`:

```
I[0] = AES_D(K, C*[0]) = [1E 7B C3 A5 F0 44 98 D2 3B 60 57 29 88 E4 0C 71]
```

---

**Step 5 — Compute IV\***

We want `P[0] = "ATTACK AT DAWN!!"`:

```
"ATTACK AT DAWN!!" in hex:
  A=41 T=54 T=54 A=41 C=43 K=4B SP=20 A=41
  T=54 SP=20 D=44 A=41 W=57 N=4E !=21 !=21

IV* = I[0] ⊕ PT[0]:
  0x1E ⊕ 0x41 = 0x5F   (I)
  0x7B ⊕ 0x54 = 0x2F   (A... wait: 'A')
  0xC3 ⊕ 0x54 = 0x97   (T)
  0xA5 ⊕ 0x41 = 0xE4   (A)
  0xF0 ⊕ 0x43 = 0xB3   (C)
  0x44 ⊕ 0x4B = 0x0F   (K)
  0x98 ⊕ 0x20 = 0xB8   ( )
  0xD2 ⊕ 0x41 = 0x93   (A)
  0x3B ⊕ 0x54 = 0x6F   (T)
  0x60 ⊕ 0x20 = 0x40   ( )
  0x57 ⊕ 0x44 = 0x13   (D)
  0x29 ⊕ 0x41 = 0x68   (A)
  0x88 ⊕ 0x57 = 0xDF   (W)
  0xE4 ⊕ 0x4E = 0xAA   (N)
  0x0C ⊕ 0x21 = 0x2D   (!)
  0x71 ⊕ 0x21 = 0x50   (!)

IV* = [5F 2F 97 E4 B3 0F B8 93 6F 40 13 68 DF AA 2D 50]
```

---

**Step 6 — Assemble the Forged Ciphertext**

```
Forged = IV*  ||  C*[0]  ||  C*[1]

       = [5F 2F 97 E4 B3 0F B8 93 6F 40 13 68 DF AA 2D 50]   ← IV*
       + [4D 2A 9F 11 D4 A7 32 8E 54 EF 00 73 C5 9C 67 F0]   ← C*[0]
       + [A3 F2 11 CC 7E 05 B9 44 60 D1 82 3F AA 91 5C 2B]   ← C*[1]
```

Send this to the server → it decrypts to `"ATTACK AT DAWN!!"` ✓

---

#### Verification

```
Server's CBC decrypt:

Block 1:
  AES_D(K, C*[1]) = I[1]
  P[1] = I[1] ⊕ C*[0]
       = I[1] ⊕ (I[1] ⊕ PT[1])   ← how we built C*[0]
       = PT[1] = b"\x10" * 16     ← valid PKCS#7 ✓

Block 0:
  AES_D(K, C*[0]) = I[0]
  P[0] = I[0] ⊕ IV*
       = I[0] ⊕ (I[0] ⊕ PT[0])   ← how we built IV*
       = PT[0] = b"ATTACK AT DAWN!!" ✓
```

---

#### Diagram — Building Backwards

```
Step 1 ─ Random last block:
                                    ┌────────────┐
                                    │   C*[1]    │ ← random
                                    └────────────┘

Step 2 ─ Oracle finds I[1]:
                                    ┌────────────┐
                          I[1] ◄────│   C*[1]    │
                                    └────────────┘

Step 3 ─ Compute C*[0] = I[1] ⊕ PT[1]:
              ┌─────────────┐          ┌────────────┐
              │   C*[0]     │──────────│   C*[1]    │
              │ =I[1]⊕PT[1]│→gives    └────────────┘
              └─────────────┘  PT[1]✓

Step 4 ─ Oracle finds I[0]:
              ┌────────────┐         ┌────────────┐
    I[0] ◄────│   C*[0]    │─────────│   C*[1]    │
              └────────────┘         └────────────┘

Step 5 ─ Compute IV* = I[0] ⊕ PT[0]:
┌────────────┐ ┌────────────┐         ┌────────────┐
│    IV*     │ │   C*[0]    │─────────│   C*[1]    │
│=I[0]⊕PT[0]│ └────────────┘         └────────────┘
└────────────┘
→ gives PT[0] ✓

Final forged ciphertext:
┌────────────┐ ┌────────────┐ ┌────────────┐
│    IV*     │ │   C*[0]    │ │   C*[1]    │
└────────────┘ └────────────┘ └────────────┘
  decrypts to: "ATTACK AT DAWN!!" + PKCS#7 ✓
```

---

#### General Algorithm (N Blocks)

```
Input: N-block PKCS#7-padded plaintext PT[0..N-1]

1.  C*[N-1] = os.urandom(16)
2.  For i = N-1 down to 0:
       I[i]    = oracle_find_intermediate(C*[i])   # ~4096 calls
       C*[i-1] = I[i] ⊕ PT[i]
3.  IV* = C*[-1]   (the last block computed in the loop)
4.  Return IV* || C*[0] || C*[1] || ... || C*[N-1]

Cost: ~4096 oracle calls per block (256 candidates × 16 bytes)
```

---

#### Complete Code

```python
import os

def poa_find_intermediate(ct_block: bytes, oracle_fn) -> bytes:
    """Find I = AES_D(K, ct_block) using the padding oracle only."""
    I = [0] * 16

    for pad_val in range(1, 17):
        pos = 16 - pad_val
        fake_iv = [0] * 16
        for j in range(pos + 1, 16):
            fake_iv[j] = I[j] ^ pad_val

        for candidate in range(256):
            fake_iv[pos] = candidate
            if oracle_fn(bytes(fake_iv), ct_block):
                if pad_val == 1 and pos > 0:
                    check = fake_iv.copy()
                    check[pos - 1] ^= 0xFF
                    if not oracle_fn(bytes(check), ct_block):
                        continue   # false positive
                I[pos] = candidate ^ pad_val
                break

    return bytes(I)


def poa_encrypt(target_plaintext: bytes, oracle_fn) -> bytes:
    """
    Forge a valid CBC ciphertext for target_plaintext.
    No key needed — only the padding oracle.

    Returns: IV* || C*[0] || ... || C*[N-1]
    """
    BS = 16

    # PKCS#7 pad
    pad_len = BS - (len(target_plaintext) % BS)
    padded  = target_plaintext + bytes([pad_len]) * pad_len
    blocks  = [padded[i:i+BS] for i in range(0, len(padded), BS)]

    # Start with a random last ciphertext block
    curr_ct = os.urandom(BS)
    result  = curr_ct

    # Work backwards through plaintext blocks
    for pt_block in reversed(blocks):
        I       = poa_find_intermediate(curr_ct, oracle_fn)
        prev_ct = bytes(i ^ p for i, p in zip(I, pt_block))
        result  = prev_ct + result
        curr_ct = prev_ct

    return result   # IV* is prepended as the first 16 bytes


# Usage:
# forged = poa_encrypt(b"ATTACK AT DAWN!!", oracle)
# send forged to server → decrypts to "ATTACK AT DAWN!!"
```

---

#### Common Mistakes

| Mistake | Effect |
|---|---|
| Forgetting the PKCS#7 padding block | Server rejects — bad padding at end |
| Building blocks in **forward** order | Wrong intermediate values, garbled output |
| Not verifying false positives | `I[15]` wrong → all subsequent bytes wrong |
| Confusing `poa_encrypt` input/output | Remember: output is `IV* || ciphertext`, not just ciphertext |

---

### 4.6. ECB vs CBC Comparison

```
┌──────────────────┬─────────────────────┬─────────────────────┐
│   Property       │        ECB          │        CBC          │
├──────────────────┼─────────────────────┼─────────────────────┤
│ Parallel Encrypt │  Yes                │ No (chained)        │
│ Parallel Decrypt │  Yes                │ Yes                 │
│ Pattern Leakage  │  Same→Same          │ Hidden (random IV)  │
│ Needs IV         │  No                 │ Yes                 │
│ Bit-flip impact  │  Only that 1 block  │ That block + next   │
│ Padding Oracle   │  N/A                │ Vulnerable          │
└──────────────────┴─────────────────────┴─────────────────────┘
```

---

## 5. Summary & Cheat Sheet

### 5.1. Attack Decision Tree

```
Encryption type?
├─ XOR / OTP
│   ├─ Known plaintext+ciphertext?  → Recover key (XOR them)
│   ├─ Key reused across messages?  → Many-time pad
│   └─ Can send arbitrary plaintext? → XOR cancellation trick
│
├─ AES-ECB
│   ├─ Can send chosen plaintext + server appends secret?
│   │   └─ Suffix → ECB byte-at-a-time (suffix attack)
│   ├─ Server prepends secret then appends your input?
│   │   └─ Prefix → ECB byte-at-a-time (prefix attack)
│   └─ Repeated ciphertext blocks?  → Pattern analysis
│
└─ AES-CBC
    ├─ Can modify IV or ciphertext?  → Bit-flipping attack
    ├─ Server tells you if padding is valid?  → Padding Oracle Decrypt
    └─ Padding oracle + need to forge?       → Padding Oracle Encrypt
```

### 5.2. Complexity

```
┌──────────────────────┬──────────────────────────────┐
│ Attack               │ Oracle / Encrypt calls       │
├──────────────────────┼──────────────────────────────┤
│ ECB byte-at-a-time   │ ~256 × flag_len              │
│ POA Decrypt          │ ~4096 × n_blocks (max)       │
│ POA Encrypt          │ ~4096 × (n_blocks + 1) (max) │
└──────────────────────┴──────────────────────────────┘
```

### 5.3. Required Imports

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from pwn import *
import os, string
```

### 5.4. Common Pitfalls

```python
# 1. PKCS#7: already 16 bytes → still adds a full extra block!
pad(b"exactly16bytes!!", 16)   # → 32 bytes, not 16!

# 2. False positive in POA: always verify the last byte
if pad_val == 1 and pos > 0:
    check[pos - 1] ^= 0xFF
    if not oracle(check, block): continue

# 3. Block extraction helper
def get_block(data: bytes, n: int) -> bytes:
    return data[n*16 : (n+1)*16]

# 4. Strip PKCS#7 manually (when unpad isn't available)
plaintext = data[:-data[-1]]
```

### 5.5. Quick Reference

```bash
# Hex to raw bytes
echo "48656c6c6f" | xxd -r -p

# XOR two hex values
python3 -c "print(hex(0x4865 ^ 0x1234))"

# AES-ECB encrypt (OpenSSL)
echo -n "plaintext" | openssl enc -aes-128-ecb \
  -K "00112233445566778899aabbccddeeff" -nosalt | xxd
```

```python
# One-liners
bytes([c ^ k for c, k in zip(ct, key)])   # XOR decrypt
bytes.fromhex("deadbeef")                 # hex → bytes
data[i*16:(i+1)*16]                       # extract block i
data[:-data[-1]]                          # strip PKCS#7
(key * (len(pt)//len(key)+1))[:len(pt)]  # repeat key to length
```

---

## 6. Practice Roadmap

```
Level 1: Foundations       Level 2: Chosen PT          Level 3: Advanced ECB
├─ XOR single-byte         ├─ XOR known-plaintext       ├─ ECB byte-at-a-time
├─ XOR hex / stream        ├─ ECB CPA single byte       ├─ ECB prefix attack
├─ OTP decrypt             └─ ECB CPA suffix            └─ ECB + HTTP / SQL input
└─ AES-ECB basic decrypt

Level 4: CBC Basics        Level 5: Padding Oracle      Boss Level
├─ CBC decrypt             ├─ POA single block          ├─ ECB prefix miniboss/boss
├─ CBC bit-flipping        ├─ POA multi-block           ├─ POA on real protocol
└─ CBC tampering           └─ POA encrypt (forgery)     └─ Combined attacks
```

---

**References:**
- [Cryptopals Challenges](https://cryptopals.com/)
- [Padding Oracle Attack Explained](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [AES Modes of Operation — Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
