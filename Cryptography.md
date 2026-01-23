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

# AES Cipher Notes

## Theory

AES (Advanced Encryption Standard) is a symmetric block cipher.

**Key facts:**
- Block size: 128 bits (16 bytes)
- Key sizes: 128, 192, or 256 bits (16, 24, or 32 bytes)
- Encrypts data in 16-byte blocks
- Same key for encryption and decryption

**Common modes:**
- **ECB** (Electronic Codebook): Each block encrypted independently (insecure, don't use)
- **CBC** (Cipher Block Chaining): Each block XORed with previous ciphertext, needs IV
- **CTR** (Counter): Stream cipher mode, needs nonce
- **GCM** (Galois/Counter Mode): Authenticated encryption, provides integrity

**Padding:**
- AES requires input to be multiple of 16 bytes
- **PKCS7**: Pad with bytes, each byte = number of padding bytes
- Example: `"HELLO"` → `"HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"`

---

## Python Examples

### Setup
```python
>>> from Crypto.Cipher import AES
>>> from Crypto.Random import get_random_bytes
>>> from Crypto.Util.Padding import pad, unpad
```

### AES-ECB (simplest, but insecure)

```python
>>> key = b'YELLOW SUBMARINE'  # 16 bytes
>>> plaintext = b'SECRET MESSAGE!!'  # 16 bytes

>>> cipher = AES.new(key, AES.MODE_ECB)
>>> ciphertext = cipher.encrypt(plaintext)
>>> ciphertext.hex()
'7c8d9c16e5d9c4e8f2b3a1d4c8e7f6a2'

>>> # Decrypt
>>> cipher = AES.new(key, AES.MODE_ECB)
>>> decrypted = cipher.decrypt(ciphertext)
>>> decrypted
b'SECRET MESSAGE!!'
```

### AES-ECB with padding

```python
>>> key = b'YELLOW SUBMARINE'
>>> plaintext = b'Hello World'  # Not 16 bytes!

>>> # Pad to 16-byte boundary
>>> padded = pad(plaintext, 16)
>>> padded
b'Hello World\x05\x05\x05\x05\x05'

>>> cipher = AES.new(key, AES.MODE_ECB)
>>> ciphertext = cipher.encrypt(padded)
>>> ciphertext.hex()
'a1b2c3d4e5f6...'

>>> # Decrypt and unpad
>>> cipher = AES.new(key, AES.MODE_ECB)
>>> decrypted = unpad(cipher.decrypt(ciphertext), 16)
>>> decrypted
b'Hello World'
```

### AES-CBC (needs IV)

```python
>>> key = get_random_bytes(16)
>>> iv = get_random_bytes(16)  # Initialization Vector
>>> plaintext = b'Secret message here'

>>> cipher = AES.new(key, AES.MODE_CBC, iv)
>>> ciphertext = cipher.encrypt(pad(plaintext, 16))
>>> ciphertext.hex()
'f3a8b7c9...'

>>> # Decrypt (need same IV!)
>>> cipher = AES.new(key, AES.MODE_CBC, iv)
>>> decrypted = unpad(cipher.decrypt(ciphertext), 16)
>>> decrypted
b'Secret message here'

>>> # Note: Store IV with ciphertext
>>> combined = iv + ciphertext
>>> # To decrypt: iv = combined[:16], ct = combined[16:]
```

### AES-CTR (stream cipher mode)

```python
>>> from Crypto.Util import Counter

>>> key = get_random_bytes(16)
>>> nonce = get_random_bytes(8)

>>> # CTR mode - no padding needed!
>>> cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
>>> plaintext = b'Any length message works!'
>>> ciphertext = cipher.encrypt(plaintext)
>>> ciphertext.hex()
'a8f7b3c4...'

>>> # Decrypt
>>> cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
>>> decrypted = cipher.decrypt(ciphertext)
>>> decrypted
b'Any length message works!'
```

### AES-GCM (authenticated encryption)

```python
>>> key = get_random_bytes(16)
>>> nonce = get_random_bytes(12)  # GCM uses 12-byte nonce

>>> cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
>>> plaintext = b'Authenticated message'
>>> ciphertext, tag = cipher.encrypt_and_digest(plaintext)

>>> ciphertext.hex()
'f8a3b2c1...'
>>> tag.hex()  # Authentication tag
'd4e5f6a7...'

>>> # Decrypt and verify
>>> cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
>>> decrypted = cipher.decrypt_and_verify(ciphertext, tag)
>>> decrypted
b'Authenticated message'

>>> # Wrong tag = exception
>>> cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
>>> cipher.decrypt_and_verify(ciphertext, b'wrong tag!!!')
ValueError: MAC check failed
```

### Working with hex/base64

```python
>>> import base64

>>> key = bytes.fromhex('0123456789abcdef0123456789abcdef')
>>> plaintext = b'Hello'

>>> cipher = AES.new(key, AES.MODE_ECB)
>>> ciphertext = cipher.encrypt(pad(plaintext, 16))

>>> # To hex
>>> ciphertext.hex()
'a7b8c9d0...'

>>> # To base64
>>> base64.b64encode(ciphertext).decode()
'p7jJ0A...'

>>> # From hex
>>> ct = bytes.fromhex('a7b8c9d0...')

>>> # From base64
>>> ct = base64.b64decode('p7jJ0A...')
```

### Encrypt/Decrypt file-like data

```python
>>> key = b'YELLOW SUBMARINE'
>>> data = b'A' * 1000  # Large data

>>> # Encrypt in ECB mode
>>> cipher = AES.new(key, AES.MODE_ECB)
>>> encrypted = cipher.encrypt(pad(data, 16))
>>> len(encrypted)
1008  # Padded to multiple of 16

>>> # Decrypt
>>> cipher = AES.new(key, AES.MODE_ECB)
>>> decrypted = unpad(cipher.decrypt(encrypted), 16)
>>> decrypted == data
True
```

### Manual padding (PKCS7)

```python
>>> def pkcs7_pad(data, block_size=16):
...     padding_len = block_size - (len(data) % block_size)
...     return data + bytes([padding_len] * padding_len)

>>> pkcs7_pad(b'HELLO')
b'HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'

>>> pkcs7_pad(b'YELLOW SUBMARINE')  # Already 16 bytes
b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

>>> def pkcs7_unpad(data):
...     padding_len = data[-1]
...     return data[:-padding_len]

>>> pkcs7_unpad(b'HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b')
b'HELLO'
```

### ECB detection (same blocks → same ciphertext)

```python
>>> key = b'YELLOW SUBMARINE'
>>> plaintext = b'A' * 48  # Three identical blocks

>>> cipher = AES.new(key, AES.MODE_ECB)
>>> ciphertext = cipher.encrypt(plaintext)

>>> # Split into blocks
>>> blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
>>> blocks[0] == blocks[1] == blocks[2]
True  # ECB encrypts identical blocks identically!

>>> # CBC would have different blocks
>>> cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
>>> ciphertext_cbc = cipher.encrypt(plaintext)
>>> blocks_cbc = [ciphertext_cbc[i:i+16] for i in range(0, len(ciphertext_cbc), 16)]
>>> blocks_cbc[0] == blocks_cbc[1]
False  # CBC produces different ciphertext
```

### Byte-at-a-time ECB decryption (oracle attack)

```python
>>> # Example: Known plaintext attack on ECB
>>> key = get_random_bytes(16)
>>> secret = b'SECRET'

>>> def encryption_oracle(data):
...     cipher = AES.new(key, AES.MODE_ECB)
...     return cipher.encrypt(pad(data + secret, 16))

>>> # Attack: Discover secret byte-by-byte
>>> # Block 1: AAAAAAAAAAAAAAA? (15 A's + 1 unknown)
>>> for guess in range(256):
...     test = b'A' * 15 + bytes([guess])
...     if encryption_oracle(test)[:16] == encryption_oracle(b'A' * 15)[:16]:
...         print(f'First byte: {chr(guess)}')
...         break
First byte: S
```

### CBC bit flipping

```python
>>> key = get_random_bytes(16)
>>> iv = get_random_bytes(16)

>>> plaintext = b'admin=false;uid='
>>> cipher = AES.new(key, AES.MODE_CBC, iv)
>>> ciphertext = cipher.encrypt(pad(plaintext, 16))

>>> # Flip bits in ciphertext to change next block's plaintext
>>> # If we XOR ciphertext[0] with X, plaintext[16] will XOR with X
>>> modified_ct = bytearray(ciphertext)
>>> # Change 'false' to 'true;' by flipping bits
>>> # (This is simplified - actual attack needs careful calculation)
```

### Common CTF patterns

**Known plaintext (e.g., flag format):**
```python
>>> # If you know ciphertext and partial plaintext
>>> known_plain = b'flag{...'
>>> ciphertext_block = bytes.fromhex('a1b2c3d4e5f6g7h8...')

>>> # In ECB, try to match patterns
>>> # In CBC, IV ⊕ plaintext = decrypted_first_block
```

**Weak keys:**
```python
>>> # Null key
>>> weak_key = b'\x00' * 16

>>> # All same byte
>>> weak_key = b'A' * 16

>>> # Common passwords
>>> from hashlib import md5
>>> weak_key = md5(b'password').digest()
```

**IV reuse in CBC:**
```python
>>> # If same IV used twice:
>>> # C1[0] ⊕ C2[0] = P1[0] ⊕ P2[0]
>>> # Can recover XOR of plaintexts
```

---

## Quick Reference

**Key sizes:**
- AES-128: 16 bytes
- AES-192: 24 bytes  
- AES-256: 32 bytes

**Block size:** Always 16 bytes

**Mode requirements:**
- ECB: Just key
- CBC: Key + IV (16 bytes)
- CTR: Key + nonce (8-16 bytes)
- GCM: Key + nonce (12 bytes recommended)

**Padding:**
```python
from Crypto.Util.Padding import pad, unpad
padded = pad(data, 16)
original = unpad(padded, 16)
```

**Random bytes:**
```python
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)
iv = get_random_bytes(16)
```

**Import shortcuts:**
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
```

**Common mistakes:**
- Forgetting to pad in ECB/CBC
- Reusing IV in CBC
- Using ECB mode (reveals patterns)
- Not storing IV/nonce with ciphertext
- Wrong key size (must be 16/24/32 bytes)
