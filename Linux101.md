# Linux Command Guide

- `$`: Commands for regular users
- `#`: Commands requiring root privileges
- Reference: [Bash Cyberciti Guide](https://bash.cyberciti.biz/guide/Main_Page)

## File and Path Management
<img width="1550" height="650" alt="image" src="https://github.com/user-attachments/assets/c53e2419-3ab0-40a0-bc22-1eb28a9a7482" />
### File Types (`ls -ld`)
<img width="1172" height="374" alt="image" src="https://github.com/user-attachments/assets/34c5d76c-adc5-4d40-a8d1-a1cd8d42f703" />

- `-`: Regular file
- `d`: Directory (a special type of file)
- `l`: Symbolic link (points to another file/directory)
- `p`: Named pipe (FIFO, used for inter-process communication)
- `c`: Character device (e.g., microphone, handles data streams)
- `b`: Block device (e.g., hard drive, handles data blocks)
- `s`: Unix socket (local network connection as a file)

### Symbolic and Hard Links
<img width="1287" height="640" alt="image" src="https://github.com/user-attachments/assets/64e3d141-7a38-4aab-92e0-946cacefafc4" />

- **Symbolic Link**: A shortcut to another file (`ln -s <source> <link>`)
- **Hard Link**: Points directly to file content (`ln <source> <link>`)
    - Deleting either file doesn’t affect the other; changes sync across links
    - Check with `file <filename>` to identify symbolic links
- Example: `ln -s data.txt data_link` (symbolic), `ln data.txt data_hard` (hard)

### File Operations
- **Read Files**:
    - `cat <file>`: Display file content
    - `grep <string> <file>`: Search for text in large files
- **Compare Files**:
    - `diff <file1> <file2>`:
        - `1a2`: Line 1 in file1 added as line 2 in file2
        - `2c2`: Line 2 in file1 changed to line 2 in file2
- **Search Files**:
    - `find .` or `find <path>`: Search from current or specified directory
    - `find -name <name>`: Search by file or path name
- **Search in Files**:
    - `/<search>`: Search forward in a file viewer
        - `n`: Next match
        - `N`: Previous match
        - `?`: Reverse search direction
- **Manual/Help**:
    - `man -k <string>` or `man -K <string>`: Search man pages for a string
    - `help <command>`: Info for built-in commands (e.g., `help cd`)

### File Globbing (Wildcards)
- `*`: Matches any characters (e.g., `echo ../*`)
- `?`: Matches a single character (e.g., `echo ../?????` for 5-character names)
- `[ab]`: Matches specific characters (e.g., `echo ../file_[ab]` for `file_a`, `file_b`)
- `[cep]*`: Matches names starting with `c`, `e`, or `p` (e.g., `echo [cep]*`)
- `[^ab]` or `[!ab]`: Excludes `a` or `b` (e.g., `echo ../file_[^ab]` for `file_c`)
## Input/Output Redirection
- **Streams**:
    - `stdin`: Input
    - `stdout` (1): Output (`echo 1 > file.txt` or `echo 1 1> file.txt`)
    - `stderr` (2): Error (`echo 1 2> error.log`)
- **Redirect Both**: `<program> 1>output.txt 2>error.log`
- **Pipe (`|`)**: Passes output of one command as input to another
- **Descriptor (`>&`)**: Redirects streams (e.g., `2>&1` sends stderr to stdout)
- **tee**: Writes input to file(s) and stdout
    - Example: `echo 1 | tee file1.txt file2.txt`
    - Debugging: `command1 | tee debug.txt | command2`

### Process Substitution
- `<(command)`: Outputs command to a temporary named pipe (`/dev/fd/63`)
    - Example: `diff <(command1) <(command2)`
    - Check: `echo <(command)` to see the pipe path
- `>(command)`: Sends input to a command
    - Example: `echo HACK | tee >(rev)` → Outputs: `HACK KCAH`
### Named Pipes (FIFO)
- Create: `mkfifo <pipe>`
- Usage:
    - Write: `echo data > myfifo` (hangs until read)
    - Read: `cat myfifo` (closes pipe after reading)
- Note: Pipes don’t use disk space and are removed after closing

## Variables
- Access: `$<variable>` (e.g., `$PWD` for current directory)
- Set: `<var>=<value>` (local to current shell)
- Export: `export <var>=<value>` (available in child shells)
- List: `env` (shows all environment variables)
- Capture Command Output:
    - `FLAG=$(cat /flag)` or `FLAG=`cat /flag``
- Read Input:
    - `read -p "Prompt: " VAR`: From keyboard
    - `read VAR < file`: From file
- Exit Code: `echo $?` (0 = success, 1 = failure)<img width="894" height="330" alt="image" src="https://github.com/user-attachments/assets/fd196e77-7358-4bca-8d07-6f710b25402c" />

## Data Manipulation
- `awk`: Complex text processing
- `cut`: Extract columns (e.g., `cut -d " " -f 1 file.txt` for first space-separated column)
- `less`: Interactive file reader
- `more`: Paginated file reader
- `paste`: Merge files line by line
- `sed`: Stream editor for text manipulation
- `sort`: Sort lines (`-r` reverse, `-n` numeric, `-u` unique, `-R` random)
- `tail`: Display end of file
- `uniq`: Filter unique lines
- **Translate (`tr`)**:
    - Replace: `echo OWN | tr O P` → `PWN`
    - Multiple Replace: `echo PWM.COLLAGE | tr MA NE` → `PWN.COLLEGE`
    - Delete: `echo OWN | tr -d "O,N"` → `W`
    - Newline: `echo OWN | tr W "\n"` → Splits to lines `O`, `N`
## Processes
- List: `ps aux` or `ps -fe` (`ps auxww` for full paths)
- Kill: `kill <pid>`
- Interrupt: `Ctrl+C`
- Suspend: `Ctrl+Z`
    - Resume: `fg` (foreground) or `bg` (background)
    - List Jobs: `jobs`
    - Switch: `fg %<job_number>`
- Run in Background: `<program> &`

## Users and Permissions
- Switch User: `su` (root) or `su <username>`
- Passwords: `/etc/shadow` (crack with `john <shadow_file>`)
- Sudo Config: `/etc/sudoers` (defines sudo privileges)
- Permissions (`ls -l`): Format `type:user:group:other` (e.g., `-rwxr-xr-x`)
    - `r`: Read (list for directories)
    - `w`: Write (modify/create/delete for directories)
    - `x`: Execute (run program or enter directory)
    - Change Owner: `chown <user> <file>`
    - Change Group: `chgrp <group> <file>`
    - Change Permissions: `chmod <who><+/-=><what> <file>`
        - `who`: `u` (user), `g` (group), `o` (other), `a` (all)
        - `what`: `r`, `w`, `x`
        - `+`: Add, `-`: Remove, `=`: Set
        - Example: `chmod a=r,u=rw file` (all read, user read/write)
- **SUID Bit**: `chmod u+s <program>` (run as owner, shown as `s` in `ls -l`)
- **Sticky Bit**: `chmod +t <dir>` (only owner can rename/delete, shown as `t`)
## Command Chaining
- `;`: Run commands sequentially
- `&&`: Run second command if first succeeds
- `||`: Run second command if first fails

## Shell Scripts

- Run: `bash file.sh`
- **Shebang**: `#!/bin/bash` (specifies interpreter)
- **Arguments**: `$1`, `$2`, etc. (e.g., `./script.sh test` → `$1` is `test`)
- **Conditionals**:
    ```bash
    if [ "$1" == "ping" ]; then
        echo "pong"
    elif [ "$1" == "hello" ]; then
        echo "Hi there!"
    else
        echo "I don't understand"
    fi
    ```
## Screen and Tmux

- **Screen**: Persistent virtual terminal
    - Start: `screen`
    - Detach: `Ctrl+A d`
    - Reattach: `screen -r` or `screen -r <name>`
    - List: `screen -ls`
    - Named Session: `screen -S <name>`
    - Windows: `Ctrl+A c` (new), `Ctrl+A n` (next), `Ctrl+A p` (previous), `Ctrl+A "` (list)
- **Tmux**: Similar, uses `Ctrl+B`
    - List: `tmux ls`
    - Reattach: `tmux attach` or `tmux a`
    - Windows: `Ctrl+B c` (new), `Ctrl+B n` (next), `Ctrl+B p` (previous), `Ctrl+B w` (list)
## PATH
- Environment variable for executable paths
- Set: `PATH=<new_path>:$PATH`
- Find Command: `which <command>`
- Exploit: Modify PATH to redirect commands (e.g., replace `vim` with a malicious script)

## `.bashrc`
- Runs on terminal startup
- Exploit: If writable, append malicious commands
- `/tmp` Exploit: Use symbolic links to append to `.bashrc` if directory is writable
    - Example: `echo "malicious_command" >> /tmp/temp_file` (link `temp_file` to `.bashrc`)
    - Note: `/tmp` often has sticky bit (`chmod +t /tmp`) to prevent abuse
- Security: `.bashrc` is readable by default; sensitive data like API keys can be exposed
## Destructive Commands
- **Fork Bomb**: `:(){ :|:& };:` (spawns processes infinitely)
- **Disk Fill**: `yes > file` (fills disk with data)
- **Wipe System**: `rm -rf /` (deletes all files, use with extreme caution)
