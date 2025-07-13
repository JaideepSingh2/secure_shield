# SecureShield Firewall - README

## Overview

**SecureShield Firewall** is a modern, GUI-based firewall solution for Linux. It provides real-time network protection, rule-based access control, activity logging, and desktop notifications, all with a unified dark theme matching the SecureShield suite. The firewall uses NFQueue and iptables for packet interception and allows users to manage rules, monitor network activity, and receive alerts for blocked connections.

---

## Features

- **Rule-Based Filtering:** Create, edit, and delete firewall rules with support for IP, port, protocol, action, priority, and descriptions.
- **Real-Time Packet Interception:** Uses NFQueue and iptables to process packets in real time.
- **Activity Logs:** View detailed logs of allowed and blocked connections, as well as system events.
- **Desktop Notifications:** Get alerts for blocked connections and firewall status changes.
- **Unified GUI:** Modern PyQt5 interface with a dark theme matching SecureShield Antivirus and Password Manager.
- **Statistics:** Monitor active connections, packets processed, and packets blocked.
- **Export Logs:** Export activity logs to CSV for analysis.
- **Admin Privileges Check:** Warns if not running with root/admin privileges.

---

## Requirements

### System Requirements

- **Linux** (Tested on openSUSE, Ubuntu, Fedora; requires iptables and NFQueue support)
- **Python 3.8+**
- **Root/Admin Privileges** (required for packet interception and iptables manipulation)

### Python Dependencies

All required Python packages are listed in `src/requirements.txt`.

#### Install System Packages (openSUSE example)

```bash
sudo zypper refresh
sudo zypper install python3 python3-pip python3-qt5 python3-psutil python3-scapy python3-netifaces iptables
```

#### Install Python Packages

```bash
pip3 install -r src/requirements.txt
```

---

## Installation

### 1. Clone or Download the Project

```bash
git clone https://github.com/yourusername/secure_shield.git
cd secure_shield/firewall
```

### 2. Prepare Data Files

- `src/data/rules.json`: Stores firewall rules.
- `src/data/config.ini`: Configuration file for firewall settings.
- `src/data/logs.json`: Stores activity and system logs.

Default files are created automatically if missing.

---

## Running SecureShield Firewall

**The firewall can only be run using the provided script. Do not run the Python files directly.**

### 1. Start the GUI

```bash
bash run_firewall.sh
```

This script ensures the firewall runs with the necessary environment variables and root privileges.

---

## Using the Application

- **Enable/Disable Firewall:** Toggle protection from the sidebar.
- **Manage Rules:** Add, edit, or delete rules in the "Firewall Rules" tab.
- **Monitor Activity:** View connection and system logs in the "Activity Logs" tab.
- **Export Logs:** Export logs to CSV for external analysis.
- **Notifications:** Receive desktop alerts for blocked connections (requires `notify-send` on Linux).
- **Statistics:** View real-time stats for connections and packets.

---

## File Structure

```
firewall/
├── src/
│   ├── main.py                # Main application entry point
│   ├── requirements.txt       # Python package requirements
│   ├── data/
│   │   ├── rules.json         # Firewall rules
│   │   ├── config.ini         # Configuration file
│   │   ├── logs.json          # Activity logs
│   ├── firewall_core/
│   │   ├── rule_manager.py    # Rule management
│   │   ├── rule_engine.py     # Rule matching engine
│   │   ├── packet_interceptor.py # Packet interception via NFQueue
│   │   ├── firewall_controller.py # Firewall lifecycle management
│   │   ├── logger.py          # Logging system
│   ├── gui/
│   │   ├── main_window.py     # Main GUI window
│   │   ├── rules_editor.py    # Rules editor widget
│   │   ├── log_viewer.py      # Activity log viewer
│   │   ├── alerts_popup.py    # Alert popups
│   │   ├── theme.qss          # Unified dark theme
│   ├── utils/
│   │   ├── permissions.py     # Admin/root privilege checks
│   │   ├── notifier.py        # Desktop notifications
│   │   ├── network_utils.py   # Network info and stats
├── run_firewall.sh            # Script to launch with proper environment
```

---

## Security Considerations

- **Admin Privileges:** The firewall requires root/admin privileges to intercept packets and modify iptables rules.
- **Rule Priority:** Higher priority rules are matched first; disabled rules are ignored.
- **Logging:** All activity and system events are logged for auditing.
- **Notifications:** Desktop notifications require `notify-send` (Linux), PowerShell (Windows), or `osascript` (macOS).

---

## Troubleshooting

- **Permissions:** If you see permission errors, always run the application using `bash run_firewall.sh`.
- **iptables/NFQueue:** Ensure `iptables` and NFQueue are available and not blocked by other firewall software.
- **Notifications:** On Linux, install `libnotify` for `notify-send` support.
- **Dependencies:** Install all packages from `src/requirements.txt`.

---

## Future Improvements

- Support for Windows and macOS (limited by packet interception capabilities).
- Advanced rule scheduling.
- Integration with SecureShield Antivirus and Password Manager.
- Remote management and cloud sync.

---

**Enjoy secure network protection