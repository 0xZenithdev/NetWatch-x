#!/usr/bin/env zsh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
NETWATCH_PATH="$SCRIPT_DIR/netwatch"
osascript -e "do shell script \"'$NETWATCH_PATH' >/dev/null 2>&1 &\" with prompt \"Comfortably monitor your network traffic.\" with administrator privileges"
