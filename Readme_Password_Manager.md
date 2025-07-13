# SecureShield Password Manager - README

## Overview

**SecureShield Password Manager** is a secure, modern password management solution for Linux. It provides encrypted storage and retrieval of user passwords for various websites and services. Key features include master password authentication, AES encryption, password generation, password strength checking, and a user-friendly GUI built with Python and Tkinter. All passwords are encrypted using strong cryptography, and the interface matches the SecureShield Antivirus style for a unified experience.

This README covers only the **Password Manager** component of SecureShield.

---

## Features

- **Master Password Authentication:** Protects access to all stored passwords.
- **Strong Encryption:** All credentials are encrypted using AES (via Fernet).
- **Password Generator:** Create secure, customizable passwords and passphrases.
- **Password Strength Checker:** Analyze password strength and get feedback.
- **Password Storage:** Add, edit, delete, and view credentials for sites and applications.
- **Notes Support:** Store additional notes with each password entry.
- **Clipboard Integration:** Copy usernames and passwords securely to clipboard.
- **Change Master Password:** Update your master password and re-encrypt all data.
- **Search & List:** Quickly find and manage stored credentials.
- **Consistent Dark-Themed GUI:** Modern Tkinter interface matching SecureShield Antivirus.

---

## Library Requirements

- pip
- tkinter
- bcrypt
- pyperclip
- xclip (Linux clipboard support)

### System Requirements

- **Linux** (Tested on openSUSE, Ubuntu, Fedora; works on most modern distributions)
- **Python 3.8+**

### Python Dependencies

All required Python packages are listed in `requirements.txt`.

#### Install System Packages (openSUSE example)

```bash
sudo zypper refresh
sudo zypper install python3 python3-pip python3-tk
```

#### Install Python Packages

```bash
pip3 install -r requirements.txt
```

---

## Encryption Technique

Passwords are protected using AES encryption via the Fernet library from the `cryptography` package. A unique encryption key is derived from the user's master password using PBKDF2HMAC.

- **Key Derivation:** PBKDF2HMAC generates a strong encryption key from the master password, using a randomly generated salt and iterative hashing to resist brute-force attacks.
- **AES Encryption:** Fernet provides a high-level interface to AES encryption, handling key management, initialization vectors, and authenticated encryption. All passwords and the password store are encrypted using this key.
- **Encryption at Rest:** All passwords and associated data are stored encrypted on disk. Even if the storage file is compromised, passwords remain protected without the master password.

---

## Design Choices

- **Modular Design:** The application separates authentication, encryption, storage, password generation, and GUI for maintainability and testability.
- **Authentication (`auth.py`):** Handles user authentication and stores a salted hash of the master password using bcrypt. Upon successful authentication, an encryption key is derived.
- **Encryption (`encryption.py`):** Uses the derived key to encrypt and decrypt passwords and the password store with Fernet (AES).
- **Password Storage (`password_store.py`):** Manages encrypted password storage in a file, with methods for adding, retrieving, updating, and deleting entries. Data is serialized to JSON before encryption.
- **Password Generation (`password_generator.py`):** Generates strong, random passwords based on user-defined criteria.
- **Password Strength (`password_strength.py`):** Assesses password strength based on length, character diversity, and common patterns.
- **GUI:** Provides a user-friendly interface using Tkinter for managing passwords, generating new passwords, and checking password strength.

---

## Security Considerations

- **Master Password Strength:** The security of the system relies on the strength of the master password. Users should choose a strong, unique password.
- **Key Derivation:** PBKDF2HMAC with a high iteration count makes brute-force attacks more difficult.
- **Memory Security:** The master password and encryption key are not stored in memory longer than necessary.
- **Clipboard Security:** When copying passwords to the clipboard, users are warned about the risk of other applications accessing clipboard data.
- **Dependency Management:** Keep external libraries (`bcrypt`, `cryptography`, `pyperclip`) up-to-date to address security vulnerabilities.
- **Common Password Check:** The application checks against a list of common passwords to prevent weak choices.

---

## Installation

### 1. Clone or Download the Project

```bash
git clone https://github.com/yourusername/secure_shield.git
cd secure_shield/password_manager
```

### 2. Prepare Common Passwords File

- Place a file named `common_pass.txt` in `password_manager/src/` for password strength analysis.
- If missing, a minimal list will be used.

---

## Running SecureShield Password Manager

### 1. Start the GUI

```bash
python3 main.py
```

### 2. Using the Application

- **First Run:** Set up your master password. This password is required to access all stored credentials.
- **Login:** Enter your master password to unlock the manager.
- **View Passwords:** See a list of all stored credentials.
- **Add/Edit/Delete:** Manage credentials for sites and applications.
- **Generate Password:** Create strong passwords with custom options.
- **Check Strength:** Analyze the security of any password.
- **Change Master Password:** Update your master password securely.
- **Copy to Clipboard:** Easily copy usernames and passwords for use.

All data is encrypted and stored locally in `passwords.enc` within the password manager directory.

---

## Example Usage & User Interface

- **Setting up a Master Password:** Weak passwords prompt a warning; users must enter a stronger password.
- **Adding a New Password:** Store credentials for any site or service.
- **Retrieving a Stored Password:** Select an entry and view details, with an option to copy to clipboard.
- **Generating a Secure Password:** Create strong passwords with customizable options.
- **Checking Password Strength:** Analyze passwords in real time; weak passwords are flagged.
- **User Interface:** Features include a login screen, password list view, add/edit form, password generator, and strength checker.

---

## File Structure

```
password_manager/
├── main.py                # Main GUI application
├── src/
│   ├── auth.py            # Master password authentication
│   ├── encryption.py      # Encryption/decryption logic
│   ├── password_store.py  # Password storage and retrieval
│   ├── password_generator.py # Password generation logic
│   ├── password_strength.py  # Password strength analysis
│   └── common_pass.txt    # List of common passwords (optional)
├── passwords.enc          # Encrypted password storage (created after first use)
├── config.json            # Master password config (created after setup)
└── requirements.txt       # Python package requirements
```

---

## Troubleshooting

- **Missing Dependencies:** Ensure all packages in `requirements.txt` are installed.
- **Corrupted Storage:** If you cannot access your passwords, check `config.json` and `passwords.enc` for corruption.
- **Common Passwords File:** For best strength analysis, provide a comprehensive `common_pass.txt` in `src/`.

---

## Conclusion

SecureShield Password Manager provides a secure and convenient way to store and manage passwords. Strong encryption and modular design protect sensitive data from unauthorized access. Future improvements may include two-factor authentication, cloud sync, and browser integration.

**Enjoy secure