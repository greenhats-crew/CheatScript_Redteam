#!/bin/bash

SESSION_NAME="logsession"

if tmux has-session -t $SESSION_NAME 2>/dev/null; then
    echo "[*] Stopping logging in session '$SESSION_NAME'..."
    tmux pipe-pane -t $SESSION_NAME -o ""
    tmux kill-session -t $SESSION_NAME
    echo "[+] Logging stopped and session killed."
else
    echo "[!] Session '$SESSION_NAME' is already existed."
fi

