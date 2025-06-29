import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class PasswordEncryption:
    def __init__(self, encryption_key=None):
        """Initialize the encryption module with an encryption key"""
        self.encryption_key = encryption_key
        self.fernet = None
        
        if encryption_key:
            self.fernet = Fernet(encryption_key)
    
    def set_encryption_key(self, encryption_key):
        """Set or update the encryption key"""
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key)
    
    def encrypt_password(self, password):
        """Encrypt a password using the encryption key"""
        if not self.fernet:
            raise ValueError("Encryption key not set. Please authenticate first.")
        
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Encrypt the password using Fernet (which uses AES)
        encrypted_password = self.fernet.encrypt(password)
        
        # Return the encrypted password as a base64 string
        return base64.b64encode(encrypted_password).decode('utf-8')
    
    def decrypt_password(self, encrypted_password):
        """Decrypt an encrypted password"""
        if not self.fernet:
            raise ValueError("Encryption key not set. Please authenticate first.")
        
        # Convert base64 string to bytes
        if isinstance(encrypted_password, str):
            encrypted_password = base64.b64decode(encrypted_password)
        
        # Decrypt the password
        decrypted_password = self.fernet.decrypt(encrypted_password)
        
        # Return the decrypted password as a string
        return decrypted_password.decode('utf-8')
    
    def encrypt_data(self, data):
        """Encrypt arbitrary data (dict, list, etc.) by converting to JSON"""
        if not self.fernet:
            raise ValueError("Encryption key not set. Please authenticate first.")
        
        # Convert data to JSON string
        json_data = json.dumps(data)
        
        # Encrypt the JSON string
        return self.encrypt_password(json_data)
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data that was encrypted with encrypt_data"""
        # Decrypt the data to get the JSON string
        json_data = self.decrypt_password(encrypted_data)
        
        # Parse the JSON string back to the original data structure
        return json.loads(json_data)