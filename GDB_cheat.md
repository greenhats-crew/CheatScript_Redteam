# GDB Cheatsheet — Complete Reverse Engineering Edition

---

## 1. Launching & Setup

```bash
gdb ./program                          # Load binary
gdb ./program core                     # Load with core dump
gdb --args ./program arg1 arg2         # Pass arguments at load time
gdb -q ./program                       # Quiet mode (no banner)
gdb -p <pid>                           # Attach to running process
gdb -batch -ex "run" -ex "bt" ./prog   # Non-interactive: run commands and exit
```

Inside GDB:

```gdb
set disassembly-flavor intel           # Intel syntax (recommended for RE)
set pagination off                     # Disable --More-- paging
set print pretty on                    # Pretty-print structs
set print array on                     # Pretty-print arrays
set follow-fork-mode child             # Follow child on fork()
set detach-on-fork off                 # Debug both parent and child
set disable-randomization on           # Disable ASLR (default: on in GDB)
set disable-randomization off          # Enable ASLR (test real behavior)
set environment LD_PRELOAD=./hook.so   # Set env var before run
set unsetenv LD_PRELOAD                # Unset env var
```

---

## 2. Running the Program

```gdb
run                                    # Run from the start
run arg1 arg2                          # Run with arguments
run < input.txt                        # Pipe input from file
run <<< $(python3 -c "print('A'*64)")  # Pipe crafted input
kill                                   # Kill current session
```

---

## 3. Breakpoints

```gdb
break main
break *0x401234
break *main+42
info breakpoints                       # List all breakpoints (alias: i b)
delete 1 / delete                      # Delete #1 / delete all
disable 2 / enable 2
clear *0x401234                        # Remove breakpoint at address
save breakpoints bp.txt                # Save to file
source bp.txt                          # Restore from file
```

### Conditional Breakpoints

```gdb
break *0x401234 if $rax == 0
break strcmp if strcmp((char*)$rdi, "secret") == 0
break *0x401234 if ((int)$rbp - (int)$rsp) > 0x100
```

### Watchpoints — Break on Memory Access

```gdb
watch *0x601060                        # Break when written
rwatch *0x601060                       # Break when read
awatch *0x601060                       # Break on read or write
watch -l var                           # Watch local variable by location
watch *(long*)($rbp - 8)              # Watch a stack variable
```

### Catchpoints — Break on Events

```gdb
catch syscall                          # Every syscall
catch syscall read write               # Only read/write
catch syscall 59                       # Syscall #59 = execve
catch exec                             # When execve() succeeds
catch fork                             # On fork()
catch throw                            # C++ exception throw
catch catch                            # C++ exception catch
catch signal SIGSEGV                   # Segfault
catch load libc                        # When shared lib is loaded
```

---

## 4. Execution Control

```gdb
continue  (c)
stepi     (si)                         # Into function calls
nexti     (ni)                         # Over function calls
step      (s)
next      (n)
finish                                 # Run until current function returns
until *0x401280                        # Run until specific address
jump *0x401234                         # Jump execution (no call frame setup)
call (void)some_func(1, 2)             # Call a function manually
```

---

## 5. Record & Reverse Debugging

The most powerful GDB feature for RE — record every instruction, then **step backwards**.

### Start / Stop

```gdb
record full                            # Software recording (universal, slower)
record btrace                          # Hardware branch tracing
record btrace bts                      # Branch Trace Store mode
record btrace pt                       # Intel Processor Trace (fastest, needs PT CPU)
record stop
record delete                          # Discard log
```

### Reverse Execution

```gdb
reverse-continue  (rc)                 # Run backwards to previous breakpoint
reverse-stepi     (rsi)                # One instruction back (into)
reverse-nexti     (rni)                # One instruction back (over)
reverse-step      (rs)                 # One source line back
reverse-finish                         # Back to entry of current function
```

### Navigating the Log

```gdb
record goto begin                      # Rewind to start of recording
record goto end                        # Jump to latest recorded instruction
record goto 42                         # Jump to instruction #42
info record                            # Status + instruction count
```

### Typical Workflows

**Find what corrupted a value:**

```gdb
break main
run
record full
continue                               # Let it reach the bad state
watch *(long*)0x404020                 # Watchpoint on corrupted memory
reverse-continue                       # Lands exactly on the write instruction
x/i $rip                              # The culprit
info frame
```

**Replay an unknown algorithm:**

```gdb
break *0x401200                        # Entry of target function
run
record full
finish                                 # Let it complete
record goto begin                      # Rewind
si                                     # Step forward carefully, inspect state
# Went past something? Just:
reverse-stepi
```

**Count instructions between two points:**

```gdb
break *0x401100
run
record full
info record                            # Note start instruction number
break *0x401200
continue
info record                            # Difference = instructions executed
```

> **Tip**: `record full` has overhead. Break before the area of interest, start recording, then crash/complete — don't record the entire run.

---

## 6. Registers

```gdb
info registers                         # All general-purpose registers
info registers rax rbp rsp rip
info all-registers                     # ALL registers including FP/SSE/AVX
p $rax                                 # Hex (default)
p/d $rax                               # Decimal
p/x $rax                               # Hex
p/t $rax                               # Binary
p/c $rax                               # ASCII char
p (char)$rax                           # Cast and print
```

### x86-64 Register Reference

|Register|Role|
|---|---|
|`rip`|Instruction pointer|
|`rsp`|Stack pointer (top of stack)|
|`rbp`|Base pointer (bottom of current frame)|
|`rax`|Return value / syscall number|
|`rdi`|Arg 1|
|`rsi`|Arg 2|
|`rdx`|Arg 3|
|`rcx`|Arg 4|
|`r8`|Arg 5|
|`r9`|Arg 6|
|`rflags`|CPU flags|

### Sub-registers (same physical register)

|64-bit|32-bit|16-bit|8-bit high|8-bit low|
|---|---|---|---|---|
|`rax`|`eax`|`ax`|`ah`|`al`|
|`rbx`|`ebx`|`bx`|`bh`|`bl`|
|`rcx`|`ecx`|`cx`|`ch`|`cl`|
|`rdx`|`edx`|`dx`|`dh`|`dl`|
|`rsi`|`esi`|`si`|—|`sil`|
|`rdi`|`edi`|`di`|—|`dil`|
|`rsp`|`esp`|`sp`|—|`spl`|
|`rbp`|`ebp`|`bp`|—|`bpl`|

```gdb
p $eax                                 # Low 32 bits of RAX
p $al                                  # Low 8 bits of RAX
p $ah                                  # Bits 8-15 of RAX
```

### RFLAGS Bits

|Bit|Flag|Set when...|
|---|---|---|
|0|CF|Carry (unsigned overflow)|
|2|PF|Parity|
|4|AF|Auxiliary carry|
|6|ZF|Result was zero (`je`/`jz` checks this)|
|7|SF|Result was negative|
|8|TF|Trap (single-step)|
|9|IF|Interrupt enable|
|11|OF|Overflow (signed overflow)|

```gdb
p $eflags
p ($eflags >> 6) & 1                   # Extract ZF
p ($eflags >> 7) & 1                   # Extract SF
set $rflags = $rflags | 0x40           # Set ZF
set $rflags = $rflags & ~0x40          # Clear ZF
set $rflags = $rflags ^ 0x40           # Flip ZF
```

### SSE / AVX / Floating Point Registers

```gdb
info all-registers                     # Includes xmm0-xmm15, ymm0-ymm15
p $xmm0                                # Print XMM0 (128-bit SSE)
p $xmm0.v4_float                       # As 4x float
p $xmm0.v2_double                      # As 2x double
p $xmm0.v16_int8                       # As 16x int8
p $xmm0.v4_int32                       # As 4x int32
p $ymm0                                # YMM (256-bit AVX)
```

---

## 7. Examining Memory

```
x/<n><u><f> <address>
```

|Field|Options|
|---|---|
|`n`|Number of units|
|`u`|`b`=1B `h`=2B `w`=4B `g`=8B|
|`f`|`x`=hex `d`=decimal `u`=unsigned `s`=string `i`=instruction `c`=char `f`=float|

```gdb
x/16xb $rsp                            # 16 raw bytes from stack
x/8xg $rsp                             # 8 qwords (64-bit words)
x/s $rdi                               # String at RDI
x/20i $rip                             # Disassemble 20 instructions
x/4xw 0x601050                         # 4 dwords at address
x/4f 0x601050                          # 4 floats at address
x/2g 0x601050                          # 2 doubles at address
```

### Printing Expressions

```gdb
p *(int*)0x601050                      # Dereference and cast
p *(char(*)[16])0x601050               # Print 16-char array
p (char*)$rdi                          # Print string from register
p *((long**)$rsp)                      # Double dereference
p/x (unsigned long)$rax << 32 | $rbx  # Combine two registers
```

---

## 8. Working with Structs & Types (Without Symbols)

When the binary is stripped, you define types yourself.

```gdb
# Define a struct manually
ptype int                              # Built-in types work
# Use Python to inspect memory as struct:
python
import struct, gdb
addr = int(gdb.parse_and_eval('$rdi'))
mem  = gdb.selected_inferior().read_memory(addr, 24)
a, b, c = struct.unpack('<QQQ', bytes(mem))
print(f"field0={a:#x}  field1={b:#x}  field2={c:#x}")
end
```

### Reading Memory as Struct in C syntax (with debug info)

```gdb
p *(struct MyStruct*)0x404050
p ((struct MyStruct*)$rdi)->field_name
```

---

## 9. Disassembly

```gdb
disassemble main
disassemble 0x401234
disassemble 0x401000, 0x401050
disassemble /r main                    # Show raw bytes
disassemble /m main                    # Interleave source (needs symbols)
```

### Common Assembly Patterns to Recognize

```asm
; Function prologue
push rbp
mov  rbp, rsp
sub  rsp, 0x40                         ; Allocate 64 bytes for locals

; Function epilogue
leave                                  ; = mov rsp, rbp / pop rbp
ret

; Reading a local variable
mov eax, DWORD PTR [rbp-0x8]

; Calling a function (args in rdi, rsi, rdx...)
mov edi, 1
mov rsi, 0x402010
mov edx, 13
call write

; Indirect call (vtable, function pointer)
call QWORD PTR [rax+0x18]             ; vtable dispatch

; Comparison + jump
cmp eax, 0
je  0x401234                          ; if (eax == 0) goto
test rax, rax                         ; like cmp rax, 0 but cheaper
jnz 0x401234                          ; if (rax != 0) goto

; Stack canary check
mov rax, QWORD PTR fs:0x28            ; Load canary
mov QWORD PTR [rbp-0x8], rax          ; Store on stack
...
xor eax, eax                          ; at end of function
cmp QWORD PTR [rbp-0x8], rax          ; Compare
jne __stack_chk_fail                  ; Smashed!
```

---

## 10. Stack Frame Analysis

```gdb
info frame                             # Current frame info
info locals                            # Locals (needs debug info)
info args                              # Function args
backtrace      (bt)                    # Full call stack
backtrace 5                            # Last 5 frames
frame 2                                # Switch to frame #2
up / down                              # Move frames
```

### Stack Frame Memory Layout (x86-64 System V ABI)

```
HIGH ADDRESS
  ...                               ← args 7+ passed on stack
  arg8           ← $rbp + 32
  arg7           ← $rbp + 24
  return address ← $rbp + 8        ← critical for ROP / overflow
  saved RBP      ← $rbp + 0        ← caller's frame pointer
  canary         ← $rbp - 8        ← (if enabled)
  local1         ← $rbp - 16
  local2         ← $rbp - 24
  ...
  $rsp           ← current top
LOW ADDRESS
```

```gdb
x/xg $rbp+8                            # Return address
x/xg $rbp                              # Saved RBP
x/xg $rbp-8                            # First local (or canary)
x/20xg $rsp                            # Visualize entire top of stack
p (long)($rbp - $rsp)                  # Frame size in bytes
```

---

## 11. Heap Inspection

```gdb
info proc mappings                     # Find heap range
p (void*)sbrk(0)                       # Current heap top (brk)

# Print a malloc'd chunk header (glibc)
# Chunk layout: [prev_size][size|flags][user_data...]
x/4xg <chunk_ptr> - 16                 # Read chunk header before user pointer
# size & 1 = PREV_INUSE
# size & 2 = IS_MMAPPED
# size & 4 = NON_MAIN_ARENA

# Walk the heap manually
# Better: use pwndbg's `heap`, `bins`, `malloc_chunk` commands
```

### pwndbg Heap Commands

```gdb
heap                                   # List all heap chunks
bins                                   # tcache / fastbins / smallbins / largebins
malloc_chunk 0x555555758260            # Inspect specific chunk
vis_heap_chunks                        # Visual heap layout
find_fake_fast 0x601060                # Find fake fastbin candidate
```

---

## 12. Multi-threading

```gdb
info threads                           # List all threads
thread 2                               # Switch to thread #2
thread apply all bt                    # Backtrace for ALL threads
thread apply all info registers        # Registers for all threads
set scheduler-locking on               # Only current thread runs (for step)
set scheduler-locking off              # All threads run (default)
set scheduler-locking step            # Lock during step, unlock on continue
break *0x401234 thread 2               # Breakpoint only for thread 2
watch *addr thread 3                   # Watchpoint only for thread 3
```

---

## 13. Remote Debugging

### gdbserver (most common — debug on another machine or QEMU)

On the target:

```bash
gdbserver :1234 ./program              # Listen on port 1234
gdbserver :1234 --attach <pid>         # Attach to running process
gdbserver --multi :1234                # Multi-process mode
```

On your machine:

```gdb
target remote 192.168.1.10:1234        # Connect to remote gdbserver
target remote :1234                    # Localhost
target extended-remote :1234           # Extended mode (run/attach commands work)
set sysroot /path/to/target/sysroot    # Load matching shared libs
set solib-search-path /path/to/libs
```

### QEMU + GDB (Kernel / Firmware RE)

```bash
# Run binary with QEMU userspace emulation + GDB stub
qemu-x86_64 -g 1234 ./program

# Run full system QEMU with GDB stub
qemu-system-x86_64 -s -S -kernel vmlinuz ...
# -s = -gdb tcp::1234
# -S = freeze at startup
```

```gdb
target remote :1234
break start_kernel
continue
```

### GDB over Serial (embedded)

```gdb
target remote /dev/ttyUSB0
set remotebaud 115200
```

---

## 14. Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited
# or
echo core > /proc/sys/kernel/core_pattern
```

```gdb
gdb ./program core                     # Load program + core
bt                                     # Backtrace at crash
info registers                         # Registers at crash time
x/20i $rip - 20                        # Instructions around crash
x/20xg $rsp                            # Stack at crash
info proc mappings                     # Memory layout at crash
```

---

## 15. Signal Handling

```gdb
info signals                           # List all signals + GDB behavior
handle SIGSEGV stop print              # Stop + print on segfault (default)
handle SIGSEGV nostop noprint pass     # Ignore, pass to program
handle SIGALRM nostop noprint pass     # Disable timer (common CTF anti-debug)
handle SIGUSR1 stop print              # Trap custom signal
handle SIGINT nostop noprint pass      # Don't intercept Ctrl+C in program
```

---

## 16. Searching Memory

```gdb
find 0x400000, 0x500000, "/bin/sh"    # Search string in range
find $rsp, $rsp+0x200, 0x41414141     # Search for 0x41414141 on stack
find /b 0x400000, +0x100000, 0x90     # Search for NOP byte
find /w 0x400000, +0x100000, 0xdeadbeef
```

---

## 17. Modifying State (Runtime Patching)

```gdb
set $rax = 0
set $rip = 0x401234                    # Redirect execution
set $rflags = $rflags ^ 0x40          # Flip ZF
set *(int*)0x601050 = 0xdeadbeef       # Patch 4 bytes at address
set *(char*)($rsp+8) = 0x41
set *(long*)($rbp+8) = 0x401234        # Overwrite return address (ROP)

# Patch opcodes in .text (NOP out an instruction)
set *(short*)0x401234 = 0x9090         # Write two NOP bytes
```

---

## 18. Auto-Display

```gdb
display/8i $rip
display/16xb $rsp
display/8xg $rsp
display $rax
info display
undisplay 1
```

---

## 19. Logging Output to File

```gdb
set logging file gdb.log              # Set output file
set logging on                        # Start logging all output
set logging off                       # Stop
set logging overwrite on              # Overwrite instead of append
set logging redirect on               # Send output ONLY to file (not terminal)
```

---

## 20. TUI (Text User Interface)

```gdb
layout regs                            # Registers + disassembly
layout asm                             # Disassembly only
layout src                             # Source code (needs symbols)
layout split                           # Source + disassembly split
tui disable                            # Back to normal CLI
focus cmd                              # Keyboard focus to command pane
refresh                                # Redraw (if glitched)
winheight asm +5                       # Resize asm window
```

---

## 21. Working with Stripped Binaries (No Symbols)

When there are no function names or variable names:

```gdb
# Find entry point
info files                             # Shows Entry point address
break *0x401060                        # Break at entry (_start)

# Manually find main (common pattern after _start)
# _start calls __libc_start_main(main, argc, argv, ...)
# RDI will hold the address of main
break *<_start_addr>
run
si                                     # Step until call __libc_start_main
p $rdi                                 # = address of main
break *$rdi
continue

# Identify functions by pattern
x/20i 0x401000                         # Disassemble and look for push rbp / mov rbp,rsp

# Assign names to addresses
set $func_check_pass = 0x401234
break *$func_check_pass

# Add a symbol manually (advanced)
add-symbol-file extra_syms.o 0x401000
```

### Useful objdump Tricks for Stripped Binaries

```bash
# List all functions by scanning for push rbp patterns
objdump -D -Mintel ./program | grep -B1 "push.*rbp" | grep "^[0-9a-f]"

# Find all cross-references to a string
strings -t x ./program | grep "password"
# Note the offset, then in GDB:
# x/s 0x<binary_load_addr> + 0x<offset>
```

---

## 22. Binary Protection Reference

|Protection|What it does|How to identify|
|---|---|---|
|**ASLR**|Randomizes base addresses of stack/heap/libs each run|`cat /proc/sys/kernel/randomize_va_space`|
|**PIE**|Position Independent Executable — binary itself also randomized|`checksec` shows `PIE enabled`|
|**NX / DEP**|Non-executable stack/heap — shellcode won't run|`checksec` shows `NX enabled`|
|**Stack Canary**|Random value before return address — detects overflows|`checksec` shows `Canary found`; look for `fs:0x28` in disasm|
|**RELRO**|Makes GOT read-only (Partial or Full)|`checksec` shows `Full RELRO`|
|**FORTIFY**|Compile-time buffer overflow checks in libc functions|`checksec`|

```bash
checksec --file=./program
```

```gdb
# Detect PIE at runtime — find binary base
info proc mappings                     # First entry = binary base if PIE
p $base = 0x555555554000              # Save base
break *($base + 0x1234)               # Break at PIE offset
```

---

## 23. Anti-Debug Bypass Techniques

### ptrace Self-Check

```gdb
# Program calls ptrace(PTRACE_TRACEME) — returns -1 if already traced
break ptrace
commands
  silent
  set $rax = 0                         # Fake success
  finish
end
```

### SIGALRM / Timeout

```gdb
handle SIGALRM nostop noprint pass
```

### Timing Checks (rdtsc)

```gdb
# Binary checks time between rdtsc calls
# Hard to patch in GDB — use record + replay, or patch the JNE after comparison
break *0x401234                        # After the time comparison
commands
  set $rflags = $rflags & ~0x40        # Force jump not taken
  continue
end
```

### /proc/self/status Check (TracerPid)

```bash
# GDB will show TracerPid != 0 in /proc/self/status
# Bypass with LD_PRELOAD hook that fakes the open/read of /proc/self/status
# Or patch the comparison in the binary
```

### isatty / Environment Checks

```gdb
break isatty
commands
  set $rax = 1                         # Pretend we have a terminal
  finish
end
```

---

## 24. Common RE Scenarios

### Find a Password / License Key

```gdb
break strcmp
commands
  silent
  printf "[strcmp]  '%s'  vs  '%s'\n", (char*)$rdi, (char*)$rsi
  continue
end

break strncmp
commands
  silent
  printf "[strncmp] '%s'  vs  '%s'  len=%d\n", (char*)$rdi, (char*)$rsi, (int)$rdx
  continue
end

break memcmp
commands
  silent
  printf "[memcmp]  len=%d\n", (int)$rdx
  x/32xb $rdi
  x/32xb $rsi
  continue
end
run
```

### Bypass a Conditional Jump

```gdb
break *0x401234
commands
  silent
  set $rflags = $rflags ^ 0x40         # Flip ZF each time we hit this
  continue
end
```

### Find Stack Buffer Overflow Offset

```bash
# Generate pattern in shell
python3 -c "import pwn; print(pwn.cyclic(200))" > pattern.txt
```

```gdb
run < pattern.txt
# On crash:
x/xg $rsp                              # Or $rip if directly overwritten
# Find offset in Python:
# python3 -c "import pwn; print(pwn.cyclic_find(0x6161616b))"
```

### Trace All Syscalls

```gdb
catch syscall
commands
  silent
  printf "[syscall #%d]  rdi=%lx  rsi=%lx  rdx=%lx\n", $rax, $rdi, $rsi, $rdx
  continue
end
```

### Inspect argv / envp

```gdb
break main
run
p (int)$rdi                            # argc
x/s *((char**)$rsi)                    # argv[0]
x/s *((char**)$rsi + 1)                # argv[1]
x/s *((char**)$rdx)                    # envp[0]
```

### Leak libc Base Address

```gdb
info proc mappings                     # Find libc range
p system                               # Print &system (once libc is loaded)
# libc_base = &system - <known offset of system in libc>
# Get offset: readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " system"
```

### GOT Overwrite (verify during exploit dev)

```gdb
x/xg 0x601018                         # Read GOT entry for e.g. puts
# After exploit:
x/xg 0x601018                         # Should now point to system()
```

### Format String Vulnerability — Leak Stack

```gdb
break printf
commands
  silent
  printf "[printf] format='%s'\n", (char*)$rdi
  x/32xg $rsp                          # Stack values = potential leaks
  continue
end
```

---

## 25. GDB Python Scripting — Full Examples

### Auto-trace strcmp (Python class style)

```python
# trace_strcmp.py
import gdb

class StrcmpTracer(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval('$rdi'))
        rsi = int(gdb.parse_and_eval('$rsi'))
        try:
            s1 = gdb.execute(f'x/s {rdi}', to_string=True).split('"')[1]
            s2 = gdb.execute(f'x/s {rsi}', to_string=True).split('"')[1]
            print(f'\033[92m[strcmp]\033[0m  "{s1}"  vs  "{s2}"')
        except Exception as e:
            print(f'[strcmp] parse error: {e}')
        return False  # Don't stop, just log

gdb.execute('set pagination off')
gdb.execute('set disassembly-flavor intel')
StrcmpTracer('strcmp')
StrcmpTracer('strncmp')
gdb.execute('run')
```

```bash
gdb -q -x trace_strcmp.py ./program
```

---

### Dump All Strings on the Stack at a Breakpoint

```python
# stack_strings.py
import gdb, struct

class StackStringDumper(gdb.Breakpoint):
    def stop(self):
        rsp = int(gdb.parse_and_eval('$rsp'))
        inf = gdb.selected_inferior()
        mem = bytes(inf.read_memory(rsp, 256))
        print(f'[stack strings @ rsp={rsp:#x}]')
        for i in range(0, len(mem) - 4):
            s = b''
            j = i
            while j < len(mem) and 0x20 <= mem[j] < 0x7f:
                s += bytes([mem[j]])
                j += 1
            if len(s) >= 5:
                print(f'  rsp+{i:#04x}: {s.decode()}')
        return True   # Stop here

StackStringDumper('*0x401234')         # Your target address
gdb.execute('run')
```

---

### Automatic Context Printer (pure GDB script)

```python
# ctx.py
import gdb

def print_context():
    print('\n' + '='*60)
    print('REGISTERS')
    print('='*60)
    for reg in ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip','eflags']:
        try:
            val = int(gdb.parse_and_eval(f'${reg}'))
            print(f'  {reg:8s} = {val:#018x}  ({val})')
        except:
            pass
    print('\nSTACK (top 8 qwords)')
    gdb.execute('x/8xg $rsp')
    print('\nNEXT INSTRUCTIONS')
    gdb.execute('x/10i $rip')

class ContextHook(gdb.Breakpoint):
    def stop(self):
        print_context()
        return True

# Hook every stop event
class StopHandler(gdb.events.stop.__class__):
    pass

gdb.events.stop.connect(lambda e: print_context())
```

---

### Session Save / Restore State

```python
# save_state.py — save register state to file
import gdb, json

def save_state(filename='state.json'):
    regs = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip','r8','r9','r10','r11','r12','r13','r14','r15']
    state = {}
    for r in regs:
        try:
            state[r] = int(gdb.parse_and_eval(f'${r}'))
        except:
            pass
    with open(filename, 'w') as f:
        json.dump(state, f, indent=2)
    print(f'[*] State saved to {filename}')

class SaveCmd(gdb.Command):
    def __init__(self):
        super().__init__('save-state', gdb.COMMAND_USER)
    def invoke(self, arg, tty):
        save_state(arg.strip() or 'state.json')

SaveCmd()
```

---

## 26. `.gdbinit` — Full Starter Config

```gdb
# ~/.gdbinit

set disassembly-flavor intel
set pagination off
set print pretty on
set print array on
set disable-randomization on

# ── Context display ──────────────────────────────────────────
define ctx
  echo \n========== REGISTERS ==========\n
  info registers rax rbx rcx rdx rsi rdi rbp rsp rip eflags
  echo \n========== STACK (top 10 qwords) ==========\n
  x/10xg $rsp
  echo \n========== NEXT INSTRUCTIONS ==========\n
  x/12i $rip
  echo \n
end

define hook-stop
  ctx
end

# ── Frame dump ───────────────────────────────────────────────
define fdump
  echo \n=== FRAME INFO ===\n
  info frame
  echo \n=== ARGS ===\n
  info args
  echo \n=== LOCALS ===\n
  info locals
end

# ── Record shortcuts ─────────────────────────────────────────
define rec
  record full
  echo [*] Recording started\n
end

define rg
  record goto $arg0
end

# ── Stack string scan ────────────────────────────────────────
define sstrings
  set $i = 0
  while $i < 64
    x/s $rsp + $i * 8
    set $i = $i + 1
  end
end

# ── Hexdump n bytes from address ─────────────────────────────
define hd
  x/$arg1xb $arg0
end
# Usage: hd $rsp 64

# ── Quick checksec via shell ─────────────────────────────────
define checksec
  shell checksec --file=$arg0 2>/dev/null || echo "checksec not installed"
end
```

---

## 27. Companion Tools

```bash
# ── Static analysis ────────────────────────────────────────────
objdump -D -Mintel ./program
objdump -D -Mintel ./program | grep -E "cmp|test|je |jne|call"

# ── Hex dump ───────────────────────────────────────────────────
xxd ./program | head -80
xxd -r patch.hex > patched              # Reverse: hex → binary

# ── Strings ────────────────────────────────────────────────────
strings ./program
strings -n 8 ./program | grep -iE "pass|key|flag|secret|admin"
strings -t x ./program                  # Show offset of each string

# ── ELF structure ──────────────────────────────────────────────
readelf -h ./program                    # ELF header (arch, entry point)
readelf -S ./program                    # Sections
readelf -l ./program                    # Segments / program headers
readelf -d ./program                    # Dynamic section (imports)
readelf --syms ./program                # Symbol table
readelf --relocs ./program              # Relocations (PLT/GOT)

# ── PLT/GOT imports ────────────────────────────────────────────
objdump -d -Mintel ./program | grep "@plt"

# ── Library / syscall tracing ──────────────────────────────────
ltrace ./program                        # Library calls
ltrace -e strcmp ./program              # Only strcmp calls
strace ./program                        # Syscalls
strace -e trace=open,read,write ./prog  # Filter
strace -o trace.txt ./program           # Save to file

# ── Binary info ────────────────────────────────────────────────
file ./program                          # Architecture, stripped, dynamic
checksec --file=./program               # All protections
ldd ./program                           # Shared library dependencies
nm ./program                            # Symbol table (not stripped)
nm -D ./program                         # Dynamic symbols

# ── Patching ───────────────────────────────────────────────────
# Find offset of byte to patch:
objdump -D -Mintel ./program | grep -n "jne"
# Then edit in hex:
printf '\x90\x90' | dd of=./program bs=1 seek=<offset> conv=notrunc
```

---

## 28. pwndbg / GEF — Enhanced GDB

```bash
# pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Add to ~/.gdbinit:
source ~/pwndbg/gdbinit.py
```

### Key Commands

|Command|What it does|
|---|---|
|`context`|Auto-print regs + stack + disasm + backtrace on every stop|
|`checksec`|Binary protections|
|`vmmap`|Full memory map with permissions|
|`heap`|List heap chunks|
|`bins`|tcache / fastbins / smallbins / largebins|
|`malloc_chunk <addr>`|Inspect one chunk|
|`vis_heap_chunks`|Visual heap layout|
|`rop`|Search ROP gadgets in binary|
|`cyclic 100`|Generate De Bruijn pattern|
|`cyclic -l 0x6161616b`|Find offset from pattern value|
|`search-pattern "/bin/sh"`|Search pattern in all memory|
|`telescope $rsp 20`|Pretty-print stack with symbol resolution|
|`got`|Print GOT table|
|`plt`|Print PLT entries|
|`xinfo 0x7ffff7a42000`|Identify what lives at an address|
|`canary`|Print current stack canary value|
|`aslr`|Show ASLR status|
|`piebase`|Print PIE base address|
|`retaddr`|Print return address locations|
|`down` / `up`|Move between stack frames|
|`syscall-args`|Show current syscall arguments nicely|

---

## 29. Quick Reference Card

```
LAUNCH          gdb -q ./prog
SETUP           set disassembly-flavor intel | set pagination off
RUN             run / run < file / run <<< $(python3 -c "...")
BREAK           b main | b *0x401234 | b *main+42
WATCH           watch *addr | rwatch | awatch
CATCH           catch syscall 59 | catch signal SIGSEGV
STEP            si (into) | ni (over) | finish | reverse-stepi
RECORD          record full | rc | rsi | record goto begin
REGISTERS       info registers | p $rax | p/d $rax | p/x $rax
FLAGS           p ($eflags>>6)&1  [ZF]  | set $rflags ^= 0x40
MEMORY          x/16xb $rsp | x/s $rdi | x/20i $rip
STACK           info frame | bt | x/xg $rbp+8 [retaddr]
PATCH           set $rax=0 | set *(int*)addr=val | set $rip=addr
SEARCH          find 0x400000,0x500000,"/bin/sh"
THREAD          info threads | thread 2 | thread apply all bt
REMOTE          target remote :1234
LOG             set logging file f.log | set logging on
AUTO-DISPLAY    display/8i $rip | display/8xg $rsp
TUI             layout regs | layout asm | tui disable
INIT            ~/.gdbinit (hook-stop, set flavor, etc.)
```

---

_Start every session: `checksec`, `file`, `info proc mappings`, `info functions`, then `record full`._
