# CPU Data Storage and Assembly Programming

## CPU Data Storage Types

- **Registers**: Fast, small storage inside the CPU for immediate data access.
- **Memory (RAM)**: Larger, slower storage for program data and variables.
- **Stack**: A special region of RAM operating on a Last-In-First-Out (LIFO) basis, used for temporary data and function calls.

---

## Bytes

### Byte Groups

| Name              | Size    | Bits |
| ----------------- | ------- | ---- |
| Nibble            | ½ byte  | 4    |
| Byte              | 1 byte  | 8    |
| Half word / Word  | 2 bytes | 16   |
| Double word (dword) | 4 bytes | 32 |
| Quad word (qword) | 8 bytes | 64   |

### Signed vs. Unsigned

- **Signed**: Can be positive or negative. The MSB (most significant bit) indicates the sign — `0` = positive, `1` = negative.
  - Example: `11111111` → `-1`, `10000000` → `-128`
- **Unsigned**: Positive only. All bits represent the value.
  - Example: `11111111` → `255`

---

## Registers

**Purpose**: Temporary storage for data and instructions during CPU processing.

### Key Registers (x86_64)

| Register | Role |
|----------|------|
| `rax` | Accumulator — used for syscall numbers and arithmetic results |
| `rdi` | 1st syscall/function argument |
| `rsi` | 2nd argument, often source index |
| `rdx` | 3rd argument, often data size |
| `rsp` | Stack pointer — tracks the top of the stack |
| `rbp` | Base pointer — marks the start of the current stack frame |
| `rip` | Instruction pointer — holds the address of the next instruction |

### Sub-Registers of `rax`

| Name | Size | Bits |
|------|------|------|
| `rax` | Full | 64-bit |
| `eax` | Lower half | 32-bit |
| `ax`  | Lower quarter | 16-bit |
| `al`  | Lowest byte | 8-bit (low) |
| `ah`  | Second byte  | 8-bit (high) |

Example: `mov al, 255` sets the lowest 8 bits of `rax`.

### 32-bit Caveat

- Writing to `eax` → CPU **zeroes out** the upper 32 bits of `rax`.
- Writing to `ax`, `al`, or `ah` → upper bits **remain unchanged**.

```asm
mov rax, 0xffffffffffffffff
mov ax, 0x539     ; rax = 0xFFFFFFFFFFFF0539
mov eax, 0x539    ; rax = 0x0000000000000539

mov eax, -1       ; rax = 0x00000000ffffffff
mov rax, -1       ; rax = 0xffffffffffffffff
```

### Extending Data

- `movsx` — sign-extending move: fills upper bits with the sign bit.

```asm
mov eax, -1       ; rax = 0x00000000ffffffff  (unsigned: 4294967295 / signed: -1)
movsx rax, eax    ; rax = 0xffffffffffffffff  (unsigned: 18446744073709551615 / signed: -1)
```

---

## Arithmetic Instructions

| Instruction     | Equivalent           | Description                                      | Example |
| --------------- | -------------------- | ------------------------------------------------ | ------- |
| `add rax, rbx`  | `rax = rax + rbx`    | Add                                              | `5+3=8` |
| `sub ebx, ecx`  | `ebx = ebx - ecx`    | Subtract                                         | `10-4=6` |
| `imul rsi, rdi` | `rsi = rsi * rdi`    | Signed multiply (truncates to 64-bit)            | `6*7=42` |
| `div reg`       | `rax = rdx:rax / reg`<br>`rdx = rdx:rax % reg` | Unsigned divide — quotient in `rax`, remainder in `rdx` | `10/3 → rax=3, rdx=1` |
| `inc rdx`       | `rdx++`              | Increment by 1                                   | `9→10` |
| `dec rdx`       | `rdx--`              | Decrement by 1                                   | `5→4` |
| `neg rax`       | `rax = 0 - rax`      | Negate                                           | `5→-5` |
| `not rax`       | `rax = ~rax`         | Bitwise NOT (flip all bits)                      | `0b1010→0b0101` |
| `and rax, rbx`  | `rax &= rbx`         | Bitwise AND                                      | `0b1100 & 0b1010 = 0b1000` |
| `or rax, rbx`   | `rax \|= rbx`        | Bitwise OR                                       | `0b1100 \| 0b1010 = 0b1110` |
| `xor rcx, rdx`  | `rcx ^= rdx`         | Bitwise XOR                                      | `0b1100 ^ 0b1010 = 0b0110` |
| `shl rax, 10`   | `rax <<= 10`         | Shift left, fill right with 0s                   | `0b1 → 0b10000000000` |
| `shr rax, 10`   | `rax >>= 10`         | Shift right, fill left with 0s                   | `0b10000000000 → 0b1` |
| `sar rax, 10`   | `rax >>= 10` (signed) | Arithmetic right shift — preserves sign bit     | `0b1111000000000000 → 0b1111111111111111` |
| `ror rax, 10`   | rotate right         | Rotate bits right by 10                          | — |
| `rol rax, 10`   | rotate left          | Rotate bits left by 10                           | — |

> **`div` special case**: If `rdx ≠ 0` before dividing, the dividend is the full 128-bit value `rdx:rax`, which can produce a wildly unexpected quotient. Always `xor rdx, rdx` (zero out `rdx`) before a simple division.

---

## Memory

- Address range: `0x10000` → `0x7fffffffffff`
- Each address references **one byte**.
  - Example: 8 bytes stored starting at `0x133337` occupy addresses `0x133337`–`0x13333e`.

---

## Stack

```
     Register │ Contents
   +───────────────────────────+
   │ rsp      │ 1337000        │─┐
   +───────────────────────────+ │
  ┌──────────────────────────────┘
  │    Address    │ Contents
  │  +────────────────────────+
  └▸ │ 1337000    │ 2         │  ◀── argc
     +────────────────────────+
     │ 1337008    │ 1234000   │──────┐
     +────────────────────────+      │
     │ 1337016    │ 1234560   │────┐ │
     +────────────────────────+    │ │
     │ 1337024    │ 0         │    │ │
     +────────────────────────+    │ │
   ┌───────────────────────────────┘ │
   │   Address   │ Contents          │
   │ │ 1234000   │ "/tmp/..."  │◀────┘ program name
   └▸│ 1234560   │ "Hi"        │       first argument
```

```
Higher addresses ↑ (older values)
──────────────────────────────────────
0x...f8     [rsp + 24]   0x12345678    ← quad 1 (oldest)
0x...f0     [rsp + 16]   0xabcdef12    ← quad 2
0x...e8     [rsp +  8]   0xdeadbeef    ← quad 3
0x...e0   ← rsp ──────   0xcafebabe    ← quad 4 (newest / top)
──────────────────────────────────────
Lower addresses ↓ (new pushes go here)

Stack grows downward → rsp decreases when pushing
```

- **Purpose**: Temporary LIFO storage in RAM.
- **`rsp`** always points to the top of the stack.

### Operations

```asm
push rax    ; decrement rsp by 8, then store rax at [rsp]
pop  rax    ; read [rsp] into rax, then increment rsp by 8
```

`push rcx` is equivalent to:
```asm
sub rsp, 8
mov [rsp], rcx
```

### Accessing Memory

```asm
mov rax, 0x12345
mov rbx, [rax]      ; load value at address 0x12345 into rbx
mov [rax], rbx      ; store rbx into address 0x12345
```

### Controlling Access Size

By default, `[reg]` moves 64-bit (8 bytes). Use size prefixes to control:

```asm
mov rax, 0x12345
mov rbx, [rax]      ; load 64-bit from 0x12345
mov rax, 0x133337
mov [rax], ebx      ; store 32-bit from ebx to 0x133337
```

### Little Endian

Memory stores values with the **least significant byte first**.

```asm
mov eax, 0xcafe
mov rcx, 0x12345
mov [rcx], eax      ; stores bytes: FE CA 00 00 at 0x12345
mov bh, [rcx]       ; bh = 0xfe  (the lowest address holds the lowest byte)
```

### Reading Stack Values

```asm
mov rax, 0
mov rbx, [rsp + rax*8]   ; read 1st qword from stack
inc rax
mov rcx, [rsp + rax*8]   ; read 2nd qword
```

Use `lea` to compute an address without reading memory:
```asm
lea rbx, [rsp + rax*8 + 5]   ; rbx = address only (no memory read)
mov rbx, [rbx]               ; now actually read from that address
```

Address formula: `reg + reg*(1|2|4|8) + offset`

### RIP-Relative Addressing

`rip` holds the address of the **next** instruction. The CPU updates it automatically after every instruction.

```asm
lea rax, [rip]       ; rax = address of next instruction
lea rax, [rip+8]     ; rax = address of next instruction + 8
mov rax, [rip]       ; read 8 bytes at the address of the next instruction
mov [rip], rax       ; overwrite the next instruction (use with caution!)
```

### Writing Directly to a Memory Address

You must specify the data size explicitly:

```asm
mov rax, 0x133337
mov DWORD PTR [rax], 0x1337    ; write 32-bit value
; equivalent: mov DWORD [rax], 0x1337
```

---

## Data Section — Defining Strings and Labels

Instead of writing strings byte-by-byte onto the stack, you can define them statically in the `.data` section and reference them by label. This is cleaner and reusable.

### Basic Syntax

```asm
.intel_syntax noprefix

.section .data
    my_string:  .asciz "/flag"      ; null-terminated string (same as .string)
    my_msg:     .ascii "Hello"      ; NOT null-terminated
    my_bytes:   .byte 0x41, 0x42    ; raw bytes: 'A', 'B'
    my_len = . - my_string          ; computed length constant

.section .text
.global _start
_start:
    lea rdi, [rip + my_string]      ; rdi = pointer to "/flag"
    mov rsi, 0                      ; O_RDONLY
    mov rax, 2                      ; syscall: open
    syscall
```

### `.asciz` vs `.ascii` vs `.string`

| Directive  | Null-terminated? | Use when...                     |
| ---------- | ---------------- | ------------------------------- |
| `.asciz`   | ✅ Yes           | General null-terminated strings |
| `.string`  | ✅ Yes           | Same as `.asciz`                |
| `.ascii`   | ❌ No            | You control the terminator manually |

### Compared to the Byte-by-Byte Approach

**Old way** (manual, error-prone):
```asm
mov BYTE PTR [rsp+0], '/'
mov BYTE PTR [rsp+1], 'f'
mov BYTE PTR [rsp+2], 'l'
mov BYTE PTR [rsp+3], 'a'
mov BYTE PTR [rsp+4], 'g'
mov BYTE PTR [rsp+5], 0       ; null terminator
mov rdi, rsp
```

**New way** (clean, reusable):
```asm
.section .data
    flag_path: .asciz "/flag"

.section .text
_start:
    lea rdi, [rip + flag_path]    ; rdi = pointer to "/flag\0"
```

### Full Example: Open and Read `/flag`

```asm
.intel_syntax noprefix

.section .data
    flag_path:  .asciz "/flag"
    buf_size = 256

.section .bss
    buf: .space buf_size           ; uninitialised buffer (256 bytes)

.section .text
.global _start
_start:
    ; open("/flag", O_RDONLY)
    lea rdi, [rip + flag_path]
    mov rsi, 0                     ; O_RDONLY
    mov rax, 2                     ; syscall: open
    syscall                        ; rax = fd

    ; read(fd, buf, 256)
    mov rdi, rax                   ; fd from open()
    lea rsi, [rip + buf]
    mov rdx, buf_size
    mov rax, 0                     ; syscall: read
    syscall                        ; rax = bytes read

    ; write(1, buf, bytes_read)
    mov rdx, rax
    lea rsi, [rip + buf]
    mov rdi, 1                     ; stdout
    mov rax, 1                     ; syscall: write
    syscall

    ; exit(0)
    mov rdi, 0
    mov rax, 60
    syscall
```

### `.bss` vs `.data`

| Section | Purpose | Initialised? |
|---------|---------|-------------|
| `.data` | Defined constants, strings | ✅ Yes — values baked into binary |
| `.bss`  | Buffers, scratch space | ❌ No — zeroed at runtime, no size in binary |

> Use `.bss` for buffers you'll write into at runtime. It saves space in the binary since the OS zeroes it for you.

---

## Control Flow

### `jmp` — Unconditional Jump

```asm
mov cx, 1337
jmp STAY_LEET
mov cx, 0          ; never executed
STAY_LEET:
    push rcx
```

### Flags Register (`rflags`)

Arithmetic and comparison instructions set these flags:

| Flag | Name | Set when... |
|------|------|-------------|
| `CF` | Carry Flag | Unsigned overflow (result exceeded 64 bits) |
| `ZF` | Zero Flag | Result is exactly 0 |
| `OF` | Overflow Flag | Signed overflow (positive↔negative wrap) |
| `SF` | Sign Flag | Result's MSB is 1 (i.e., negative) |

### `cmp` and `test`

```asm
; cmp: performs subtraction, discards result, sets flags
mov eax, 5
cmp eax, 10        ; 5 - 10 = -5 (not stored)
                   ; CF=1, ZF=0, SF=1, OF=0
jnz NOT_EQUAL      ; jump if ZF=0
je  EQUAL          ; jump if ZF=1

; test: performs AND, discards result, sets flags
mov eax, 0x10
test eax, eax      ; eax & eax = 0x10 (not stored)
                   ; ZF=0, SF=0
jnz NON_ZERO
jz  IS_ZERO
```

### Conditional Jump Table

| Instruction | Meaning | Flag Condition |
|-------------|---------|----------------|
| `je` / `jz`   | Equal / Zero          | ZF = 1 |
| `jne` / `jnz` | Not equal / Not zero  | ZF = 0 |
| `jg`          | Greater (signed)      | ZF=0 and SF=OF |
| `jl`          | Less (signed)         | SF ≠ OF |
| `jge`         | Greater or equal (signed) | SF=OF |
| `jle`         | Less or equal (signed)    | ZF=1 or SF≠OF |
| `ja`          | Above (unsigned)      | CF=0 and ZF=0 |
| `jb`          | Below (unsigned)      | CF=1 |
| `jae`         | Above or equal (unsigned) | CF=0 |
| `jbe`         | Below or equal (unsigned) | CF=1 or ZF=1 |
| `js`          | Negative              | SF=1 |
| `jns`         | Non-negative          | SF=0 |
| `jo`          | Overflow              | OF=1 |
| `jno`         | No overflow           | OF=0 |

### Loop with Conditional Jump

```asm
; Count to 10
mov rax, 0
LOOP_HEADER:
    inc rax
    cmp rax, 10
    jb LOOP_HEADER      ; jump if rax < 10 (unsigned)
; rax = 10 here
```

---

## `call` and `ret`

- `call label` → pushes the current `rip` (return address) onto the stack, then jumps to `label`.
- `ret` → pops the return address from the stack back into `rip`.

### Calling Conventions

| Architecture | Argument Registers | Return | Extra args |
|---|---|---|---|
| x86 (32-bit) | Pushed on stack (reverse order) | `eax` | — |
| amd64 (64-bit) | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` | `rax` | Rest on stack |
| ARM | `r0`–`r3` | `r0` | — |

```asm
; Caller
mov rdi, 5
mov rsi, 10
call add_numbers

; Callee
add_numbers:
    mov rax, rdi
    add rax, rsi
    ret
```

### Register Save Responsibilities (amd64)

| Type | Registers | Who saves? |
|------|-----------|-----------|
| Callee-saved | `rbx`, `rbp`, `r12`–`r15` | Callee must push/pop |
| Caller-saved | `rax`, `rdi`–`r11` | Caller must save before `call` if needed |
| Special | `rsp` | Both — must always be valid |

```asm
callee:
    push rbx           ; save caller's rbx
    mov  rbx, 123
    ; ... work ...
    pop  rbx           ; restore before returning
    ret
```

---

## System Calls

**Purpose**: Ask the OS kernel to perform privileged operations on behalf of your program.

**Convention**: Place the syscall number in `rax`, arguments in `rdi`, `rsi`, `rdx` (etc.), then execute `syscall`.

```asm
; read(0, buf, 100)
mov rdi, 0          ; fd = stdin
mov rsi, rsp        ; buffer
mov rdx, 100        ; byte count
mov rax, 0          ; syscall: read
syscall             ; returns bytes read in rax

; write(1, buf, n)
mov rdi, 1          ; fd = stdout
mov rsi, rsp
mov rdx, rax        ; bytes to write = bytes read
mov rax, 1          ; syscall: write
syscall
```

### Common Syscalls (Linux x86_64)

| Syscall | Purpose | Return |
|---------|---------|--------|
| `read(fd, buf, count)` | Read bytes from fd | Bytes read |
| `write(fd, buf, count)` | Write bytes to fd | Bytes written |
| `open(path, flags)` | Open a file | File descriptor |
| `fork()` | Create child process | 0 (child) / PID (parent) |
| `execve(filename, argv, envp)` | Replace process image | No return on success |
| `wait(status)` | Wait for child to exit | Child PID |
| `exit(code)` | Terminate process | — |

### String Arguments via `.data` (preferred)

See the **Data Section** chapter above. No more byte-by-byte stack writes.

---

## Building a Program

```asm
.intel_syntax noprefix
.global _start
_start:
    mov rdi, 42     ; exit code
    mov rax, 60     ; syscall: exit
    syscall
```

```bash
# Assemble + link (no C runtime)
as -o program.o program.s
ld -o program program.o

# Or with gcc
gcc -no-pie -nostdlib -o program program.s

# Run
./program
echo $?              # prints exit code

# Disassemble
objdump -M intel -d program

# Dump only .text section
objcopy --dump-section=.text=program.text program
```

### Debugging

```asm
mov rdi, 42
mov rax, 60
int3                 ; software breakpoint — triggers the debugger
syscall
```

| Tool | Purpose |
|------|---------|
| `gdb <file>` + `starti` | Step through from the very first instruction |
| `strace ./program` | Trace all syscalls made at runtime |
| `rappel` | REPL for testing individual assembly instructions |

---

## Tips & Tricks

### Fast Modulo (Powers of 2)

Use sub-registers instead of `div` to get `% 256` or `% 65536` for free:
- `al` holds the low byte → equivalent to `value % 256`
- `ax` holds the low 2 bytes → equivalent to `value % 65536`

### `.rept` Directive

Repeat an instruction `n` times at assemble time:

```asm
.rept 5
    nop
.endr
```

### Stack Frame

A stack frame is the region of stack memory a function uses for its local variables and saved registers.

- `rbp` marks a fixed base; `rsp` moves downward to allocate space.
- Local variables live **below** `rbp` (e.g., `[rbp - 8]`).
- Restore `rsp = rbp` before `ret` to clean up.

```asm
; Allocate 5 dwords and set list[2] = 1337
mov rbp, rsp
sub rsp, 0x14          ; 5 * 4 = 20 bytes

mov eax, 1337
mov [rbp - 0xc], eax   ; list[2]

mov rsp, rbp
ret
```
