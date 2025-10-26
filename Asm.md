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
| Instruction      | C / Math Equivalent                     | Description | Example |
|------------------|------------------------------------------|-------------|----------|
| `add rax, rbx`   | `rax = rax + rbx`                       | Add `rbx` to `rax` | `rax=5`, `rbx=3` → `rax=8` |
| `sub ebx, ecx`   | `ebx = ebx - ecx`                       | Subtract `ecx` from `ebx` | `ebx=10`, `ecx=4` → `ebx=6` |
| `imul rsi, rdi`  | `rsi = rsi * rdi`                       | Multiply `rsi` by `rdi`, truncate to 64 bits | `rsi=6`, `rdi=7` → `rsi=42` |
| `inc rdx`        | `rdx = rdx + 1`                         | Increment `rdx` by 1 | `rdx=9` → `rdx=10` |
| `dec rdx`        | `rdx = rdx - 1`                         | Decrement `rdx` by 1 | `rdx=5` → `rdx=4` |
| `neg rax`        | `rax = 0 - rax`                         | Negate numerical value of `rax` | `rax=5` → `rax=-5` |
| `not rax`        | `rax = ~rax`                            | Invert each bit of `rax` (bitwise NOT) | `rax=0b1010` → `rax=0b0101` |
| `and rax, rbx`   | `rax = rax & rbx`                       | Bitwise AND between `rax` and `rbx` | `rax=0b1100`, `rbx=0b1010` → `rax=0b1000` |
| `or rax, rbx`    | `rax = rax \| rbx`                      | Bitwise OR between `rax` and `rbx` | `rax=0b1100`, `rbx=0b1010` → `rax=0b1110` |
| `xor rcx, rdx`   | `rcx = rcx ^ rdx`                       | Bitwise XOR (don’t confuse `^` with exponent) | `rcx=0b1100`, `rdx=0b1010` → `rcx=0b0110` |
| `shl rax, 10`    | `rax = rax << 10`                       | Shift bits of `rax` left by 10, fill right with 0s | `rax=0b1` → `rax=0b10000000000` |
| `shr rax, 10`    | `rax = rax >> 10`                       | Shift bits of `rax` right by 10, fill left with 0s | `rax=0b10000000000` → `rax=0b1` |
| `sar rax, 10`    | `rax = rax >> 10`                       | Arithmetic right shift — keeps sign bit (sign-extends) | `rax=0b1111000000000000` → `rax=0b1111111111111111` |
| `ror rax, 10`    | `rax = (rax >> 10) \| (rax << 54)`      | Rotate bits of `rax` right by 10 | `rax=0x123456789ABCDEF0` → rotated right by 10 bits |
| `rol rax, 10`    | `rax = (rax << 10) \| (rax >> 54)`      | Rotate bits of `rax` left by 10 | `rax=0x123456789ABCDEF0` → rotated left by 10 bits |


## Memory
- Address: 0x10000 -> 0x7fffffffffff
  - Each memory address references one byte in memory
    - Example: 8 bytes store at `0x133337` to `0x13333e` 
    
### Stack
- **Purpose**: Temporary storage in RAM, operates as LIFO.
- **Operations**:
    - `push rax`: Pushes `rax` value onto stack.
    - `pop rax`: Pops top stack value into `rax`.
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

## Assembly 101
- **Instructions**:
    - `mov rax, 60`: Moves value 60 into `rax` (e.g., for `exit` system call).
    - `mov rdi, 42`: Sets return code 42 in `rdi`.
    - `syscall`: Executes system call based on `rax` value.
- **System Call Codes**: Find codes in `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` (e.g., `cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep __NR_`).

### Writing an Assembly Program
- **Steps**:
    1. Write the program (`.s` file).
    2. Assemble to object file: `as -o program.o program.s`.
    3. Link to executable: `ld -o program program.o` (links object files, including libraries).
- **Example Program (`program.s`)**:
    ```s
    .intel_syntax noprefix
    .global _start
    _start:
        mov rax, 60    # Exit system call
        mov rdi, 42    # Return code
        syscall
    ```
    - `.intel_syntax noprefix`: Use Intel syntax without `%` prefix for registers.
    - `.global _start`: Marks `_start` as the program entry point.

### Debugging Tools
- **strace**: Tracks system calls made by a program.
    - Example: `strace ./program` shows calls like `exit(42)`.
- **GDB (GNU Debugger)**:
    - Run: `gdb <file>`.
    - Start at first instruction: `starti`.

## Memory
- **Address Range**: `0x10000` to `0x7fffffffffff` (x86_64 process memory).
- **Byte Addressing**: Each memory address holds 1 byte (8 bits).
- **Little-Endian**: Stores multi-byte data with the least significant byte first.
    - Example: Value `0x12345678` at address `0x1000` is stored as `78 56 34 12`.

### Memory Operations
- **Dereferencing**: Access value at a memory address stored in a register.
    - Example:
        ```s
        mov rax, 0x133700  # Address 0x133700 contains 42
        mov rdi, rax       # rdi = 0x133700
        mov rdi, [rax]     # rdi = 42 (dereferences address in rax)
        ```
        
- **Direct Memory Access**:
    - `mov rdi, [0x123456]`: Load value from address `0x123456`.
    - `mov [0x123456], rdi`: Store `rdi` value to address `0x123456`.
    - Note: Cannot move immediate values directly to memory (e.g., `mov [0x123456], 12` is invalid).
- **Memory Sizes**:
    - Byte: 8 bits
    - Word: 16 bits
    - Double Word: 32 bits
    - Quad Word: 64 bits

## Stack
- **Purpose**: Temporary storage in RAM, operates as LIFO.
- **Operations**:
    - `push rax`: Pushes `rax` value onto stack.
    - `pop rax`: Pops top stack value into `rax`.
- **Stack Pointer**: `rsp` register tracks the top of the stack.
- **Memory Transfer**:
    - `mov [rax], rbx`: Store `rbx` value at address in `rax`.
    - `mov rbx, [rax]`: Load value from address in `rax` to `rbx`.

## System Calls
- **Purpose**: Interface for programs to interact with the OS.
- **Mechanism**: Set `rax` to system call number, arguments in `rdi`, `rsi`, `rdx`, then execute `syscall`.
- **Examples**:
    - **Read**: `rax = 0`, `rdi` = file descriptor (e.g., 0 for stdin), `rsi` = buffer address, `rdx` = length.
    - **Write**: `rax = 1`, `rdi` = file descriptor (e.g., 1 for stdout), `rsi` = buffer address, `rdx` = length.

## Arithmetic Operations
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

### Fast Modulo (Optimization)
- Modulo powers of 2 (e.g., `x % 256`):
    - Use lower bits: `al` (8 bits) for `% 256`, `ax` (16 bits) for `% 65536`.
    - Example: `mov al, [value]` gets `value % 256`.

## Control Flow
### Jump Instructions

- **Purpose**: Change `rip` (instruction pointer) to control program flow.
- **Types**:
    - **Relative**: `jmp label` (offset from current instruction).
    - **Absolute**: `jmp 0x401000` (specific address).
    - **Indirect**: `jmp rax` or `jmp [mem]` (address in register/memory).
- **Call**: Like `jmp`, but pushes return address to stack for `ret` to use.
    - Exploit: Overwrite stack return address to redirect execution.

### Comparison (`cmp`)
- **Syntax**: `cmp a, b` (computes `a - b`, updates flags).
- **Flags**:
    - `ZF` (Zero Flag): Set if `a == b`.
    - `SF` (Sign Flag): Set if result is negative.
    - `OF` (Overflow Flag): Set if signed overflow occurs.
    - `CF` (Carry Flag): Set for unsigned borrow/overflow.
- **Examples**:
    - `cmp eax, 5` (eax = 5): `ZF=1` (equal).
    - `cmp eax, 5` (eax = 7): `ZF=0`, `SF=0` (greater, signed).
    - `cmp eax, 5` (eax = -3): `ZF=0`, `SF=1` (less, signed).
    - `cmp eax, -1` (eax = 2147483647): `OF=1` (signed overflow).

### Conditional Jumps
- **Basic**:
    - `je`/`jz`: Jump if equal (`ZF=1`).
    - `jne`/`jnz`: Jump if not equal (`ZF=0`).
- **Signed Comparisons**:
    - `jg`: Greater (`ZF=0 & SF=OF`).
    - `jge`: Greater or equal (`SF=OF`).
    - `jl`: Less (`SF≠OF`).
    - `jle`: Less or equal (`ZF=1 | SF≠OF`).
- **Unsigned Comparisons**:
    - `ja`: Above (`CF=0 & ZF=0`).
    - `jae`: Above or equal (`CF=0`).
    - `jb`: Below (`CF=1`).
    - `jbe`: Below or equal (`CF=1 | ZF=1`).

### Examples
- **Equality Check**:
    ```s
    cmp eax, ebx
    je equal
    mov ecx, 1
    jmp end
    equal:
        mov ecx, 2
    end:
    ```
    
- **Loop (Count Down)**:
    ```s
    mov ecx, 5
    loop_start:
        dec ecx
        jnz loop_start  # Jump if ecx != 0
    ```
    
- **Signed vs Unsigned**:
    ```s
    mov eax, -1
    cmp eax, 5
    jg signed_greater   # -1 > 5? (false, signed)
    ja unsigned_greater # 0xFFFFFFFF > 5? (true, unsigned)
    ```
    

### Loops and Repetition

- **`.rept` Directive**:
    ```s
    .rept 5
        nop
    .endr
    ```
    Repeats `nop` 5 times during assembly.
- **Loop Example**:
    
    ```s
    mov rax, 0
    loop_header:
        inc rax
        cmp rax, 10
        jb loop_header  # Jump if rax < 10 (unsigned)
    ```
    
    Loops until `rax = 10`.

## Signed vs Unsigned

- **Signed (2’s Complement)**: High bit indicates sign (e.g., `11111111b = -1`).
- **Unsigned**: High bit is part of value (e.g., `11111111b = 255`).
- Impacts comparisons and arithmetic (e.g., `jg` vs `ja`).

## Security Notes

- **Stack Exploits**: Overwriting return addresses in `call`/`ret` can redirect execution.
- **System Calls**: Misconfigured arguments in `rdi`, `rsi`, `rdx` can lead to vulnerabilities.
- **Debugging**: Use `strace` and `gdb` to analyze and exploit program behavior.
