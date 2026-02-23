# CPU Data Storage and Assembly Programming

## CPU Data Storage Types
- **Registers**: Fast, small storage inside the CPU for immediate data access.
- **Memory (RAM)**: Larger, slower storage for program data and variables.
- **Stack**: A special region of RAM operating on a Last-In-First-Out (LIFO) basis, used for temporary data and function calls.
## Bytes
### Group Bytes
- **Nibble**: half of a byte, 4 bits
- **Byte**: 1 byte, 8 bits
- **Half word / "word"**: 2 bytes, 16 bits
- **Double word (dword)**: 4 bytes, 32 bits
- **Quad word (qword)**: 8 bytes, 64 bits
### Sign and Unsign
- **Signed**: can be positive or negative.
  - The highest bit (MSB) shows the sign (0 = positive, 1 = negative). (Example: 11111111 -> -1, 10000000 -> -128  )
- **Unsigned**: only positive numbers.
  - All bits are used for the value. (Example: 11111111 → 255)


## Registers
- **Purpose**: Temporary storage for data and instructions during processing.
- **Key Registers (x86_64)**:
    - `rax`: Accumulator, used for system calls and arithmetic results.
    - `rdi`: First argument for system calls.
    - `rsi`: Second argument, often source index.
    - `rdx`: Third argument, often data extension.
    - `rsp`: Stack pointer, points to the top of the stack.
    - `rbp`: Holds a fixed address marking the start of the current stack frame for reliable access to locals and parameters.
    - `rip`: Instruction pointer, points to the next instruction to execute.
- **Sub-Registers**: Smaller portions of `rax` (e.g., `eax` (32-bit), `ax` (16-bit), `al` (8-bit low), `ah` (8-bit high)).
    - Example: `mov al, 255` sets the lowest 8 bits of `rax`.<img width="1683" height="592" alt="image" src="https://github.com/user-attachments/assets/96bff60a-abc4-43c4-90df-87f30b887bdd" /><img width="543" height="798" alt="image" src="https://github.com/user-attachments/assets/7727ff70-f790-4a74-84ae-a5e7913522af" />
- **32-bit Caveat**
    - Writing to eax ->  CPU zeros out the upper 32 bits of rax.
    - Writing to ax, al, or ah -> upper bits remain unchanged.
    - Example:
    ```s
    mov rax, 0xffffffffffffffff
    mov ax, 0x539     ; rax = 0xFFFFFFFFFFFF0539
    mov eax, 0x539    ; rax = 0x0000000000000539

    mov eax, -1 ; rax = 0x00000000ffffffff
    mov rax, -1 ; rax = 0xffffffffffffffff
    ```
- **Extending data**:
      - `movsx`: sign-extending move
    ```s
    mov eax, -1 ; rax = 0x00000000ffffffff (unsiged: 4294967295/ signed: -1)
    movsx eax, -1 ; rax = 0xffffffffffffffff (unsiged: 18446744073709551615 / signed: -1)
    ```
### Arithmetic
| Instruction     | C / Math Equivalent                                | Description                                                                                   | Example                                             |
| --------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `add rax, rbx`  | `rax = rax + rbx`                                  | Add `rbx` to `rax`                                                                            | `rax=5`, `rbx=3` → `rax=8`                          |
| `sub ebx, ecx`  | `ebx = ebx - ecx`                                  | Subtract `ecx` from `ebx`                                                                     | `ebx=10`, `ecx=4` → `ebx=6`                         |
| `imul rsi, rdi` | `rsi = rsi * rdi`                                  | Multiply `rsi` by `rdi`, truncate to 64 bits                                                  | `rsi=6`, `rdi=7` → `rsi=42`                         |
| `div reg`   | `rax = (rdx:rax) / reg`<br>`rdx = (rdx:rax) % reg` | Unsigned divide — divides 128-bit dividend (`rdx:rax`) by `reg`.<br>Stores **quotient** in `rax` and **remainder** in `rdx`. | **Normal case:**<br>`mov rax, 10`<br>`mov rdx, 0`<br>`mov rcx, 3`<br>`div rcx` → `rax=3`, `rdx=1`<br><br>**Special case (`rdx≠0`):**<br>`mov rax, 10`<br>`mov rdx, 2`<br>`mov rcx, 3`<br>`div rcx` → `rax=12297829382473034414`, `rdx=0` |
| `inc rdx`       | `rdx = rdx + 1`                                    | Increment `rdx` by 1                                                                          | `rdx=9` → `rdx=10`                                  |
| `dec rdx`       | `rdx = rdx - 1`                                    | Decrement `rdx` by 1                                                                          | `rdx=5` → `rdx=4`                                   |
| `neg rax`       | `rax = 0 - rax`                                    | Negate numerical value of `rax`                                                               | `rax=5` → `rax=-5`                                  |
| `not rax`       | `rax = ~rax`                                       | Invert each bit of `rax` (bitwise NOT)                                                        | `rax=0b1010` → `rax=0b0101`                         |
| `and rax, rbx`  | `rax = rax & rbx`                                  | Bitwise AND between `rax` and `rbx`                                                           | `rax=0b1100`, `rbx=0b1010` → `rax=0b1000`           |
| `or rax, rbx`   | `rax = rax \| rbx`                                 | Bitwise OR between `rax` and `rbx`                                                            | `rax=0b1100`, `rbx=0b1010` → `rax=0b1110`           |
| `xor rcx, rdx`  | `rcx = rcx ^ rdx`                                  | Bitwise XOR (don’t confuse `^` with exponent)                                                 | `rcx=0b1100`, `rdx=0b1010` → `rcx=0b0110`           |
| `shl rax, 10`   | `rax = rax << 10`                                  | Shift bits of `rax` left by 10, fill right with 0s                                            | `rax=0b1` → `rax=0b10000000000`                     |
| `shr rax, 10`   | `rax = rax >> 10`                                  | Shift bits of `rax` right by 10, fill left with 0s                                            | `rax=0b10000000000` → `rax=0b1`                     |
| `sar rax, 10`   | `rax = rax >> 10`                                  | Arithmetic right shift — keeps sign bit (sign-extends)                                        | `rax=0b1111000000000000` → `rax=0b1111111111111111` |
| `ror rax, 10`   | `rax = (rax >> 10) \| (rax << 54)`                 | Rotate bits of `rax` right by 10                                                              | `rax=0x123456789ABCDEF0` → rotated right by 10 bits |
| `rol rax, 10`   | `rax = (rax << 10) \| (rax >> 54)`                 | Rotate bits of `rax` left by 10                                                               | `rax=0x123456789ABCDEF0` → rotated left by 10 bits  |
| Instruction | C / Math Equivalent                                | Description                                                                                                                  | Example                                            



## Memory
- Address: 0x10000 -> 0x7fffffffffff
  - Each memory address references one byte in memory
    - Example: 8 bytes store at `0x133337` to `0x13333e` 
    
### Stack
```
     Register │ Contents
   +───────────────────────────+
   │ rsp      │ 1337000        │─┐
   +───────────────────────────+ │
                                 │
  ┌──────────────────────────────┘
  │
  │    Address    │ Contents
  │  +────────────────────────+
  │  │ ...        │ ...       │
  │  +────────────────────────+
  └▸ │ 1337000    │ 2         │  ◀── the ARGument Count (termed "argc")
     +────────────────────────+
     │ 1337008    │ 1234000   │──────┐
     +────────────────────────+      │
     │ 1337016    │ 1234560   │────┐ │
     +────────────────────────+    │ │
     │ 1337024    │ 0         │    │ │
     +────────────────────────+    │ │
                                   │ │
   ┌───────────────────────────────┘ │
   │                                 │
   │   Address   │ Contents          │
   │ +──────────────────────────+    │
   │ │ 1234000   │ "/tmp/..."   │◀───┘ the program name
   │ +──────────────────────────+
   │ │ ...       │ ...          │
   │ +──────────────────────────+
   └▸│ 1234560   │ "Hi"         │ the first argument!
     +──────────────────────────+
```
- **Purpose**: Temporary storage in RAM, operates as LIFO.
- **Operations**:
    - `push rax`: Pushes `rax` value onto stack.
    - `pop rax`: Pops top stack value into `rax`.
      - The pop instruction is purpose-built for this. pop rdi does two things:
        1. Reads the value at [rsp] into rdi (just like `mov rdi, [rsp]`).
        2. Adds 8 to rsp, advancing the stack pointer to the next value.

- **Stack Pointer**: `rsp` register tracks the top of the stack.
- **Memory Transfer**:
    - `mov [rax], rbx`: Store `rbx` value at address in `rax`.
    - `mov rbx, [rax]`: Load value from address in `rax` to `rbx`.
### Accessing memory
- Using `[<register_store_memoryaddress>]`
  - Example:
  ```s
  ; Move value of 0x12345 into rbx
  mov rax, 0x12345
  mov rbx, [rax]
  ; Store value of rbx into 0x12345
  mov rax, 0x12345
  mov [rax], rbx
  ```
- `push`
```s
push rcx
; Same thing
sub rsp, 8 ; Cause each memory address references one byte in memory
mov [rsp], rcx
```
### Control size
- `[<register_store_memoryaddress>]` stores 8 bits by default. To load or store 32-bit or 64-bit data to/from another memory location, two registers are required: one for the memory address and one for the data.
```s
mov rax, 0x12345    ; rax = address 0x12345
mov rbx, [rax]      ; load 64-bit from 0x12345 to rbx
mov rax, 0x133337   ; rax = address 0x133337
mov [rax], ebx      ; store 32-bit from ebx to 0x133337
```
### Little endian
- Memory is stored in little endian, meaning the highest byte of a register is stored at the lowest memory address.
- Example
  ```s
  mov eax, 0xcafe ; eax = 0xcafe
  mov rcx, 0x12345 ; rcx = address 0x12345
  mov [rcx], eax ; store 32-bit from eax to 0x12345 
  mov bh, [rcx] ; load 8-bit high from 0x12345 to bh -> bh=fe
  ```
### Copy Stack Value
- Get values from the stack (useful for debugging or inspecting memory).
```s
mov rax, 0 ; rax = 0
mov rbx, [rsp + rax*8] ; read first qword from stack
inc rax
mov rcx, [rsp + rax*8]; read next qword
```
- Use `lea` to compute an address without reading memory.
```s
lea rbx, [rsp + rax*8 + 5]       ; rbx = computed address (for checking or later use)
mov rbx, [rbx]                   ; read qword at that address
```
- **Formula**: `reg+reg*(2 or 4 or 8)+value`

### RIP (Instruction pointer register)
- Holds the address of the next instruction to execute.
- CPU automatically updates it after each instruction (like how `rsp` moves on the stack).
```s
lea rax, [rip] # load the address of the next instruction into rax
lea rax, [rip+8] # the address of the next instruction, plus 8 bytes
mov rax, [rip] # load 8 bytes from the location pointed to by the address of the next instruction
mov [rip], rax # write 8 bytes over the next instruction (CAVEATS APPLY
```
### Write directly into a memory address
- Must specify the data size when writing to memory.
- Depending on the assembler, you may use DWORD or DWORD PTR
```s
mov rax, 0x133337              ; target memory address
mov DWORD PTR [rax], 0x1337    ; write 32-bit value (0x1337) to [rax]
; same as mov DWORD [rax], 0x1337 
```

## Control Flow
### Jmp (jump)
- Skip x bytes and resume execution.
```s
mov cx, 1337
jmp STAY_LEET
mov cx, 0 ; skip
STAY_LEET:
  push rcx
```
#### Condition
- Conditions stored in the "flags" register: rflags (set rflag to 1)
    - Carry Flag (`CF`): Set if the 65th bit is 1, meaning there was an unsigned overflow.
    - Zero Flag (`ZF`): Set if the result is 0.
    - Overflow Flag (`OF`): Set if the result overflowed the signed range, i.e., wrapped from positive to negative or vice versa (signed overflow).
    - Signed Flag (`SF`): Set if the most significant bit (sign bit) of the result is 1 → the result is negative.
- These flags are affected by instructions like `cmp` (temp value using `sub`) or test(temp value using `AND`) and are then used for conditional jumps.
```s
  ; ---------- CMP example ----------
  mov eax, 5          ; eax = 5
  cmp eax, 10         ; compare eax with 10 (eax - 10, result NOT stored, temp value = -5)
                      ; Flags updated:
                      ; CF = 1  -> unsigned 5 < 10
                      ; ZF = 0  -> result != 0
                      ; SF = 1  -> signed result negative
                      ; OF = 0  -> no signed overflow
  
  jnz NOT_EQUAL       ; jump if ZF = 0 (i.e., eax != 10)
  je  EQUAL           ; jump if ZF = 1 (i.e., eax == 10)
```
  ump-section
```s
; ---------- TEST example ----------
mov eax, 0x10       ; eax = 0x10
test eax, eax       ; AND eax with itself (result NOT stored, temp value = 0x10)
                    ; Flags updated:
                    ; ZF = 0  -> eax != 0
                    ; SF = 0  -> most significant bit not set
                    ; CF = 0, OF = 0 usually cleared

jnz NON_ZERO        ; jump if eax != 0
jz  IS_ZERO         ; jump if eax == 0
```
#### Condition jmp
| Jump | Meaning | Condition (flags) |
|------|---------|------------------|
| je   | jump if equal | ZF = 1 |
| jne  | jump if not equal | ZF = 0 |
| jg   | jump if greater (signed) | ZF = 0 and SF = OF |
| jl   | jump if less (signed) | SF != OF |
| jle  | jump if less or equal (signed) | ZF = 1 or SF != OF |
| jge  | jump if greater or equal (signed) | SF = OF |
| ja   | jump if above (unsigned) | CF = 0 and ZF = 0 |
| jb   | jump if below (unsigned) | CF = 1 |
| jae  | jump if above or equal (unsigned) | CF = 0 |
| jbe  | jump if below or equal (unsigned) | CF = 1 or ZF = 1 |
| js   | jump if signed | SF = 1 |
| jns  | jump if not signed | SF = 0 |
| jo   | jump if overflow | OF = 1 |
| jno  | jump if not overflow | OF = 0 |
| jz   | jump if zero | ZF = 1 |
| jnz  | jump if not zero | ZF = 0 |

#### loop using condition jump
```s
; Example: this counts to 10!
mov rax, 0
LOOP_HEADER:
inc rax
cmp rax, 10
jb LOOP_HEADER
; now rax is 10!
```

### call
- Jumps to a function by pushing (`call` -> meaning `push`) the current RIP (instruction pointer) onto the stack, so that after the function finishes, execution returns (`ret` -> meaning `pop`) to the original RIP.<img width="1269" height="481" alt="image" src="https://github.com/user-attachments/assets/438dc240-3201-40d5-86df-a4cc401d3cc8" />
#### Calling Conventions
- **Caller:** The function that calls another function.  
    - Responsible for passing arguments and handling the return value.
- **Callee:** The function being called.  
    - Responsible for preserving certain registers and returning a result.
  
| Architecture | Argument Passing | Return Register | Notes |
|---------------|------------------|-----------------|--------|
| **x86 (32-bit)** | Push arguments (in reverse order) onto the stack | `eax` | Caller pushes args before `call`, callee returns value in `eax` |
| **amd64 (64-bit)** | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` | `rax` | First 6 args in registers, rest on stack |
| **ARM** | `r0`, `r1`, `r2`, `r3` | `r0` | Same idea — first few args in registers |

```s
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
- **Register Responsibilities (amd64)**
  
| Register Type | Registers | Responsible Function | Description |
|----------------|------------|-----------------------|-------------|
| **Callee-saved** | `rbx`, `rbp`, `r12–r15` | **Callee** | Must preserve their values (save/restore on stack) |
| **Caller-saved** | `rax`, `rdi–r11` | **Caller** | Caller must save them before `call` if needed |
| **Special** | `rsp` | Both | Stack pointer must always remain valid |

```s
; Callee-saved
callee:
    push rbx        ; save old rbx
    mov  rbx, 123
    ; ... do something ...
    pop  rbx        ; restore before returning
    ret
```

## System Call
- **Purpose**: Interface for programs to interact with the OS.
- **Mechanism**: Set `rax` to system call number, arguments in `rdi`, `rsi`, `rdx`, then execute `syscall`.
```s
; n = read(0, buf, 100);
mov rdi, 0        ; stdin (file descriptor = 0)
mov rsi, rsp       ; buffer on stack
mov rdx, 100       ; 100 bytes
mov rax, 0         ; syscall number = 0 (read)
syscall            ; Read up to 100 bytes from stdin, and return the number of bytes actually read in rax. Because it call read() -> return rax  

; write(1, buf, n)
mov rdi, 1        ; stdout (file descriptor = 1)
mov rsi, rsp       ; buffer on stack (data we read earlier)
mov rdx, rax       ; number of bytes to write = number of bytes we just read
mov rax, 1         ; syscall number for write
syscall            ; write data to stdout
```
- Linux provides 300+ system calls.
    - Each syscall has a unique ID number (placed in `rax` before syscall).
      
| System Call                    | Purpose                                         | Return Value                     |
| ------------------------------ | ----------------------------------------------- | -------------------------------- |
| `open(path, flags)`            | Opens a file                                    | New file descriptor (fd)         |
| `read(fd, buf, count)`         | Reads data from a file descriptor into memory   | Number of bytes actually read    |
| `write(fd, buf, count)`        | Writes data from memory to a file descriptor    | Number of bytes written          |
| `fork()`                       | Creates a child process                         | 0 (child), PID of child (parent) |
| `execve(filename, argv, envp)` | Replaces the current process with a new program | No return if successful          |
| `wait(status)`                 | Waits for a child process to finish             | PID of the terminated child      |

- Some system calls accept string arguments (e.g. file paths). A string is stored as contiguous bytes in memory and terminated by a 0 byte (null terminator).
```s
mov BYTE PTR [rsp+0], '/'   ; '/'
mov BYTE PTR [rsp+1], 'f'   ; 'f'
mov BYTE PTR [rsp+2], 'l'   ; 'l'
mov BYTE PTR [rsp+3], 'a'   ; 'a'
mov BYTE PTR [rsp+4], 'g'   ; 'g'
mov BYTE PTR [rsp+5], 0     ; null terminator '\0'

; open() "/flag"
mov rdi, rsp   ; rdi = pointer to "/flag"
mov rsi, 0     ; flags = O_RDONLY (read only) - Define Constant Arguments 
mov rax, 2     ; syscall number for open()
syscall        ; perform the system call
```
  - Constant Arguments <img width="1180" height="621" alt="image" src="https://github.com/user-attachments/assets/73b8907a-1ecd-4a4f-a3b5-77631cb65d3e" />

## Build Program
```s
.intel_syntax noprefix
.global _start
_start:
    mov rdi, 42    ; exit code
    mov rax, 60    ; syscall: exit
    syscall
```
```c
# compile & link (no C runtime)
gcc -no-pie -nostdlib -o quitter quitter.s
OR
as -o quitter.o quitter.s
ld -o quitter quitter.o // link object file
# run
./quitter
# check exit code (should print 42)
echo $?

# Dissembly program
objdump -M intel -d quitter

# Dump .text section (program part only - not including header)
objcopy --dump-section=.text=quitter_textsection quitter
```
- **Debug**
```s
mov rdi, 42 // our program's return code (e.g., for bash scripts)
mov rax, 60 // system call number of exit()
int3 // trigger the debugger with a breakpoint!
syscall // do the system call
```
- Tool: `gdb`, `strace`, `Rappel`
    - **strace**: Tracks system calls made by a program.
      - Example: `strace ./program` shows calls like `exit(42)`.
    - **GDB (GNU Debugger)**:
      - Run: `gdb <file>`.
      - Start at first instruction: `starti`.
### Writing an Assembly Program
- **Steps**:
    1. Write the program (`.s` file).
    2. Assemble to object file: `as -o program.o program.s`.
    3. Link to executable: `ld -o program program.o` (links object files, including libraries).

## Nice to known
### Fast Modulo (Optimization)
- Modulo powers of 2 (e.g., `x % 256`):
    - Use lower bits: `al` (8 bits) for `% 256`, `ax` (16 bits) for `% 65536`.
    - Example: `mov al, [value]` gets `value % 256`.
### Arithmetic Operations
- `add reg1, reg2`: `reg1 += reg2`
- `sub reg1, reg2`: `reg1 -= reg2`
- `imul reg1, reg2`: `reg1 *= reg2` (signed multiplication)
- `mul reg1`: `rax *= reg1` (unsigned, result in `rax`, overflow in `rdx`)
- `div reg1`: `rax / reg1` (quotient in `rax`, remainder in `rdx`)
- **Bit Shifting**:
    - `shl reg, n`: Shift left by `n` bits (multiply by 2^n^).
    - `shr reg, n`: Shift right by `n` bits (divide by 2^n^).
    - Example: `shl rax, 1` (5 → 10), `shr rax, 1` (10 → 5).
- **Logical Operations**:
    - `and reg1, reg2`: Bitwise AND.
    - `or reg1, reg2`: Bitwise OR.
    - `xor reg1, reg2`: Bitwise XOR.
    - `not reg`: Bitwise NOT.
    - Example: `c = a AND b` → `c AND a = c`, `c AND b = c`.
### Loops and Repetition
- **`.rept` Directive**:
    - Example: Repeats `nop` 5 times during assembly.
    ```s
    .rept 5
        nop
    .endr
    ```
- **Loop Example**:
    - Example: Loops until `rax = 10`.  
    ```s
    mov rax, 0
    loop_header:
        inc rax
        cmp rax, 10
        jb loop_header  # Jump if rax < 10 (unsigned)
    ```
### Stack Frame
- A stack frame is the memory region a function uses for its local variables and saved registers.
- `rbp` marks the fixed base of the frame, while `rsp` moves to allocate or free space.
- Local variables live **below** `rbp` (e.g., `[rbp - offset]`) because the stack grows downward.
- Before returning, the function restores `rsp` to `rbp` to reset the stack.

- **Example (allocate 5 dwords and set `list[2] = 1337`):**
```asm
mov rbp, rsp        ; create frame base
sub rsp, 0x14       ; allocate 5 dwords (5 * 4 bytes)

mov eax, 1337
mov [rbp-0xc], eax  ; write to list[2]

mov rsp, rbp        ; clean up frame
ret
```


