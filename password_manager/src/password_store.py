import os
import json
from .encryption import PasswordEncryption

class PasswordStore:
    def __init__(self, storage_file="passwords.enc", encryption=None):
        """Initialize the password storage system"""
        self.storage_file = storage_file
        self.encryption = encryption
        self.passwords = {}
        
        # Load passwords if the storage file exists
        if os.path.exists(storage_file):
            self.load_passwords()
    
    def set_encryption(self, encryption):
        """Set the encryption module"""
        self.encryption = encryption
    
    def load_passwords(self):
        """Load encrypted passwords from storage file"""
        if not self.encryption:
            raise ValueError("Encryption not set. Please authenticate first.")
        
        try:
            with open(self.storage_file, 'r') as file:
                encrypted_data = file.read().strip()
                if encrypted_data:
                    self.passwords = self.encryption.decrypt_data(encrypted_data)
                else:
                    self.passwords = {}
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            # If the file doesn't exist or is corrupted, start with an empty dictionary
            self.passwords = {}
    
    def save_passwords(self):
        """Save encrypted passwords to storage file"""
        if not self.encryption:
            raise ValueError("Encryption not set. Please authenticate first.")
        
        encrypted_data = self.encryption.encrypt_data(self.passwords)
        
        with open(self.storage_file, 'w') as file:
            file.write(encrypted_data)
    
    def add_password(self, site, username, password, notes=""):
        """Add or update a password entry"""
        self.passwords[site] = {
            "username": username,
            "password": password,
            "notes": notes
        }
        self.save_passwords()
    
    def get_password(self, site):
        """Retrieve a password entry"""
        return self.passwords.get(site)
    
    def delete_password(self, site):
        """Delete a password entry"""
        if site in self.passwords:
            del self.passwords[site]
            self.save_passwords()
            return True
        return False
    
    def get_all_sites(self):
        """Get a list of all stored sites"""
        return list(self.passwords.keys())
    
    def search_sites(self, query):
        """Search for sites containing the query string"""
        query = query.lower()
        return [site for site in self.passwords if query in site.lower()]