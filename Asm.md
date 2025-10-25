# CPU Data Storage and Assembly Programming

## CPU Data Storage Types
- **Registers**: Fast, small storage inside the CPU for immediate data access.
- **Memory (RAM)**: Larger, slower storage for program data and variables.
- **Stack**: A special region of RAM operating on a Last-In-First-Out (LIFO) basis, used for temporary data and function calls.
## Group Bytes
- **Nibble**: half of a byte, 4 bits
- **Byte**: 1 byte, 8 bits
- **Half word / "word"**: 2 bytes, 16 bits
- **Double word (dword)**: 4 bytes, 32 bits
- **Quad word (qword)**: 8 bytes, 64 bits

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
    - Example: `mov al, 255` sets the lowest 8 bits of `rax`.

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
