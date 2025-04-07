#!/bin/bash

mkdir -p logs
LOGFILE=logs/session_$(date +%F_%H-%M-%S).log
echo "[+] Logging to: $LOGFILE"
tmux new-session -s logsession \; \
    pipe-pane -o "tee $LOGFILE"

