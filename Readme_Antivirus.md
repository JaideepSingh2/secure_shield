# SecureShield Antivirus - README

## Overview

**SecureShield Antivirus** is a comprehensive, GUI-based antivirus solution for Linux systems. It provides real-time protection, manual scanning, threat management, and exception handling, all powered by YARA rules and a modern Python/Tkinter interface.

This README covers only the **Antivirus** component of SecureShield. Password Manager and Firewall modules are not included.

---

## Features

- **Manual File & Directory Scanning:** Scan individual files or entire directories for malware and threats.
- **Real-Time Monitoring:** Monitor directories for file changes and automatically scan new or modified files.
- **YARA-Based Detection:** Uses YARA rules for flexible and powerful malware detection.
- **Exceptions Management:** Add files or directories to an exceptions list to exclude them from scanning.
- **Threat & Scan History:** View detailed logs of past scans and detected threats.
- **Modern GUI:** Built with Python Tkinter, featuring a dark theme and intuitive controls.
- **Multi-threaded & Responsive:** Scanning and monitoring run in background threads for smooth user experience.
- **Detailed Logging:** All scan and threat events are logged.
- **Customizable:** Easily add your own YARA rules for custom threat detection.

---

## Requirements (openSUSE)

### System Requirements

- **Linux** (tested on Opensuse Tumbleweed and Leap; works on any Linux distribution)
- **Python 3.8+**
- **GCC** (for compiling C components)
- **YARA** (YARA engine and Python bindings)

### Install System Packages

Open a terminal and run:

```bash
sudo zypper refresh
sudo zypper install gcc python3 python3-pip python3-tk python3-pillow libyara-devel
```

### Install Python Packages

```bash
pip3 install pillow yara-python
```

---

## Installation & Setup

### 1. Clone or Download the Project

```bash
git clone https://github.com/yourusername/secure_shield.git
cd secure_shield/antivirus
```

### 2. Compile C Components

#### Compile the Engine

```bash
gcc -o engine engine.c -lyara
```

#### Compile the Real-Time Monitor

```bash
gcc -o rtm rtm.c -lpthread
chmod +x rtm
```

> **Note:** If you encounter errors about missing YARA headers or libraries, ensure `libyara-devel` is installed.

### 3. Prepare YARA Rules

- Place your YARA rule files (`.yar` or `.yara`) in the `antivirus/rules/` directory.
- Example rule files can be found at [YARA-Rules GitHub](https://github.com/Yara-Rules/rules).

### 4. Prepare Images

- Place the required image files (logo, icons) in `antivirus/images/`.
- Required images:
  - `logo.png`
  - `scan_file.png`
  - `scan_folder.png`
  - `rtm_config.png`
  - `warning.png`
  - `shield.png`

---

## Running SecureShield Antivirus

### 1. Start the GUI

Navigate to the project root:

```bash
cd /home/jaideep/Study_Material/Projects/secure_shield
python3 main.py
```

### 2. Using the Application

#### Home Screen

- **Scan File:** Click to select and scan a single file.
- **Scan Directory:** Click to select and scan an entire directory.
- **Real-Time Monitoring:** Configure directories to monitor for live protection.
- **History:** View past scans and detected threats.
- **Exceptions:** Manage files and directories excluded from scanning.

#### Manual Scanning

- Select a file or directory.
- The scan progress and results will be shown in a popup window.
- If threats are found, you will be prompted to delete the file or add it to exceptions.

#### Real-Time Monitoring

- Add one or more directories to monitor.
- Click "Enable Protection" to start monitoring.
- Threats detected in monitored directories will trigger alerts and popups.

#### Exceptions Management

- Add files or directories to the exceptions list to exclude them from scanning and monitoring.
- Remove exceptions as needed.

#### History

- View scan history and threat history.
- Filter by scan type or date range.

---

## Database

- All scan history, threat history, and exceptions are stored in `antivirus/secureshield.db` (SQLite).
- No external database setup required.
- The database is automatically created and managed by the application.

---

## Advanced Usage

- **Custom YARA Rules:** Add your own `.yar` or `.yara` files to `antivirus/rules/` to extend detection capabilities.
- **Database Backup:** Copy `antivirus/secureshield.db` to back up your scan history and exceptions.
- **Scan Logs:** View detailed logs for each scan, including all engine output and detection events.

---

## Troubleshooting

- **YARA Errors:** Ensure your rule files are valid and compatible with your YARA version. Use `libyara-devel` for development headers.
- **Missing Images:** The GUI will fallback to text if images are missing, but for best appearance, provide all required images.
- **Permissions:** Make sure `engine` and `rtm` are executable (`chmod +x engine rtm`).
- **Python Errors:** Ensure all dependencies are installed and you are using Python 3.
- **Database Issues:** If you encounter database errors, delete or move `secureshield.db` and restart the application to recreate it.

---

## File Structure

```
secure_shield/
├── antivirus/
│   ├── engine.c
│   ├── rtm.c
│   ├── engine      # compiled binary
│   ├── rtm         # compiled binary
│   ├── rules/      # YARA rule files (.yar, .yara)
│   ├── images/     # GUI icons and logo
│   ├── secureshield.db  # SQLite database
│   └── ...
├── main.py         # Main GUI application
└── ...
```

---

## Notes

- The application is designed for desktop use and is not intended for server environments.
- All scanning and monitoring is performed locally; no data is sent to external servers.
- For best results, keep your YARA rules up to date.

---

**Enjoy safe computing with
