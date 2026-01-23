# XOR Cipher

## Theory

XOR (exclusive OR) returns 1 when bits differ, 0 when same.

**Truth table:**
```
0 ^ 0 = 0
0 ^ 1 = 1
1 ^ 0 = 1
1 ^ 1 = 0
```

**Key properties:**
- `A ^ B = B ^ A` (commutative)
- `A ^ A = 0` (self-inverse)
- `A ^ 0 = A` (identity)
- `A ^ B ^ B = A` (reversible)

**Encryption/Decryption:**
```
ciphertext = plaintext ^ key
plaintext = ciphertext ^ key
```

## One-Time Pad (OTP)

Perfect secrecy requires:
- Key is truly random
- Key length ≥ message length
- Key used only once
- Key kept secret

**Why key reuse breaks security:**
```
C1 = M1 ^ K
C2 = M2 ^ K
C1 ^ C2 = M1 ^ M2  (key cancels out!)
```

---

## Python Examples

### Basic integer XOR
```python
>>> 10 ^ 7
13

>>> bin(10)
'0b1010'
>>> bin(7)
'0b111'
>>> bin(10 ^ 7)
'0b1101'

>>> 13 ^ 7  # decrypt
10
```

### Using pwntools strxor (recommended)

```python
>>> from pwn import xor, strxor

>>> # Simple XOR
>>> xor('A', 'B')
b'\x03'

>>> xor(b'HELLO', b'WORLD')
b'\x1f\n\x1e\x00\x0b'

>>> # strxor - XOR two equal-length strings
>>> strxor(b'HELLO', b'XMCKL')
b'\x10\x00\x0e\x06\x07'

>>> # Decrypt
>>> strxor(b'\x10\x00\x0e\x06\x07', b'XMCKL')
b'HELLO'
```

### XOR with different datatypes (manual way)

**Bytes:**
```python
>>> b'A'[0] ^ b'B'[0]
3

>>> bytes([65 ^ 66])
b'\x03'

>>> chr(65 ^ 3)
'B'
```

**Strings (char by char):**
```python
>>> ord('H') ^ ord('K')
3

>>> chr(ord('H') ^ ord('K'))
'\x03'

>>> chr(ord('H') ^ 3)
'K'
```

**Multiple bytes (without pwntools):**
```python
>>> data = b'HELLO'
>>> key = b'XMCKL'
>>> encrypted = bytes([d ^ k for d, k in zip(data, key)])
>>> encrypted
b'\x10\x00\x0e\x06\x07'

>>> decrypted = bytes([e ^ k for e, k in zip(encrypted, key)])
>>> decrypted
b'HELLO'
```

### Repeating key XOR

**Using pwntools:**
```python
>>> from pwn import xor

>>> plaintext = b'SECRET MESSAGE'
>>> key = b'KEY'

>>> encrypted = xor(plaintext, key)
>>> encrypted.hex()
'18070c0d1611481c070c180c1e07'

>>> decrypted = xor(encrypted, key)
>>> decrypted
b'SECRET MESSAGE'
```

**Manual way:**
```python
>>> plaintext = b'SECRET MESSAGE'
>>> key = b'KEY'

>>> encrypted = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])
>>> encrypted.hex()
'18070c0d1611481c070c180c1e07'

>>> decrypted = bytes([encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))])
>>> decrypted
b'SECRET MESSAGE'
```

### Hex string XOR

**Using pwntools:**
```python
>>> from pwn import xor

>>> hex1 = '1c0111'
>>> hex2 = '686974'

>>> result = xor(bytes.fromhex(hex1), bytes.fromhex(hex2))
>>> result.hex()
'746865'

>>> result
b'the'
```

**Manual way:**
```python
>>> hex1 = '1c0111'
>>> hex2 = '686974'

>>> bytes1 = bytes.fromhex(hex1)
>>> bytes2 = bytes.fromhex(hex2)
>>> result = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])
>>> result.hex()
'746865'

>>> result
b'the'
```

### UTF-8 handling

```python
>>> text = 'Hello'
>>> key = 'key'

>>> text_bytes = text.encode('utf-8')
>>> key_bytes = key.encode('utf-8')
>>> encrypted = bytes([text_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(text_bytes))])
>>> encrypted
b'#\x00\x1b\x13\x18'

>>> decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))])
>>> decrypted.decode('utf-8')
'Hello'
```

### Base64 XOR

```python
>>> import base64
>>> data = base64.b64decode('SGVsbG8=')  # 'Hello'
>>> data
b'Hello'

>>> key = b'ABC'
>>> encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
>>> encrypted
b'\n\'\x0f\x0f\x0e'

>>> base64.b64encode(encrypted).decode()
'Cicf'
```

### Single byte XOR crack

```python
>>> ciphertext = bytes.fromhex('1b37373331363f')

>>> for key in range(256):
...     plain = bytes([b ^ key for b in ciphertext])
...     if all(32 <= b < 127 for b in plain):
...         print(f'{key:3d} ({chr(key)}): {plain}')
88 (X): b"Cooking"
```

### XOR two ciphertexts (key reuse)

```python
>>> c1 = bytes.fromhex('0e33')
>>> c2 = bytes.fromhex('2b1c')

>>> c1_xor_c2 = bytes([b1 ^ b2 for b1, b2 in zip(c1, c2)])
>>> c1_xor_c2
b'%/'

>>> # If we know plaintext1
>>> p1 = b'Hi'
>>> p2 = bytes([b1 ^ b2 for b1, b2 in zip(c1_xor_c2, p1)])
>>> p2
b'md'
```

### Mixed encoding example

```python
>>> # ASCII to hex
>>> text = 'AB'
>>> hex_result = ''.join(f'{ord(c):02x}' for c in text)
>>> hex_result
'4142'

>>> # Hex XOR
>>> bytes.fromhex('4142') ^ bytes.fromhex('0101')
Traceback (most recent call last):
TypeError: unsupported operand type(s) for ^: 'bytes' and 'bytes'

>>> # Correct way:
>>> a = bytes.fromhex('4142')
>>> b = bytes.fromhex('0101')
>>> bytes([x ^ y for x, y in zip(a, b)])
b'@C'

>>> bytes([x ^ y for x, y in zip(a, b)]).hex()
'4043'
```

### Common patterns

**Check if encrypted with single byte:**
```python
>>> cipher = b'\x20\x25\x2c\x2c\x2f'
>>> for k in range(256):
...     plain = bytes([b ^ k for b in cipher])
...     if plain.isalpha():
...         print(f'{k}: {plain}')
77: b'HELLO'
```

**Hamming distance (for key length detection):**
```python
>>> def hamming(b1, b2):
...     return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

>>> hamming(b'this', b'that')
2
```

---

## Quick Reference

**Convert between formats:**
```python
'A' → ord('A') → 65
65 → chr(65) → 'A'
65 → hex(65) → '0x41'
'41' → int('41', 16) → 65
b'A' → b'A'[0] → 65
```

**Common XOR operations:**
```python
int ^ int         → int
bytes[i] ^ int    → int
ord(char) ^ int   → int
```

**Remember:** XOR is reversible, so `(A ^ B) ^ B = A`
