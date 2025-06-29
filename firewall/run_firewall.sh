# pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" python3 /home/jaideep/Study_Material/Projects/Antivirus/fw/FirewallGUI/main.py
# pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 /home/jaideep/Study_Material/Projects/Antivirus/fw/FirewallGUI/main.py

#!/bin/bash

# Save environment variables
export DISPLAY_VAL="$DISPLAY" 
export XAUTH_VAL="$XAUTHORITY"
export DBUS_VAL="$DBUS_SESSION_BUS_ADDRESS"

# Use pkexec with properly quoted environment variables
pkexec env DISPLAY="$DISPLAY_VAL" XAUTHORITY="$XAUTH_VAL" DBUS_SESSION_BUS_ADDRESS="$DBUS_VAL" python3 /home/jaideep/Study_Material/Projects/Antivirus/fw/FirewallGUI/src/main.py