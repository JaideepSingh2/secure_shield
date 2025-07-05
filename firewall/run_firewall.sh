#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Save environment variables
export DISPLAY_VAL="$DISPLAY" 
export XAUTH_VAL="$XAUTHORITY"
export DBUS_VAL="$DBUS_SESSION_BUS_ADDRESS"

# Use pkexec with properly quoted environment variables and relative path
pkexec env DISPLAY="$DISPLAY_VAL" XAUTHORITY="$XAUTH_VAL" DBUS_SESSION_BUS_ADDRESS="$DBUS_VAL" python3 "$SCRIPT_DIR/src/main.py"