import os
import json
import bcrypt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class MasterPasswordAuth:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.salt = None
        self.master_hash = None
        self.encryption_key = None
        
        # Create config directory if it doesn't exist
        config_dir = os.path.dirname(os.path.abspath(self.config_file))
        if config_dir:  # Only create directory if there's a directory path
            os.makedirs(config_dir, exist_ok=True)
        
        # Load config if exists
        if os.path.exists(self.config_file):
            self._load_config()
    
    def _load_config(self):
        """Load the configuration (salt and password hash) from file"""
        try:
            with open(self.config_file, 'r') as file:
                config = json.load(file)
                self.salt = base64.b64decode(config.get('salt', ''))
                self.master_hash = base64.b64decode(config.get('master_hash', ''))
        except (json.JSONDecodeError, FileNotFoundError):
            # Handle corrupt or missing config file
            self.salt = None
            self.master_hash = None

    def _save_config(self):
        """Save the configuration (salt and password hash) to file"""
        config = {
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'master_hash': base64.b64encode(self.master_hash).decode('utf-8')
        }
        
        with open(self.config_file, 'w') as file:
            json.dump(config, file, indent=2)

    def is_configured(self):
        """Check if the master password has been set up"""
        return self.salt is not None and self.master_hash is not None

    def setup_master_password(self, master_password):
        """Set up the master password for the first time"""
        # Generate a random salt
        self.salt = os.urandom(16)
        
        # Hash the master password with the salt
        self.master_hash = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt())
        
        # Save the configuration
        self._save_config()
        
        # Generate and store the encryption key
        self.encryption_key = self._derive_key(master_password)
        
        return True

    def authenticate(self, master_password):
        """Authenticate the user with the master password"""
        if not self.is_configured():
            return False
        
        # Check if the provided password matches the stored hash
        if bcrypt.checkpw(master_password.encode('utf-8'), self.master_hash):
            # Generate the encryption key for later use
            self.encryption_key = self._derive_key(master_password)
            return True
        
        return False

    def _derive_key(self, master_password):
        """Derive an encryption key from the master password using PBKDF2"""
        if self.salt is None:
            raise ValueError("Salt is not set. Please set up the master password first.")
        
        # Use PBKDF2 to derive a key from the master password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
        return key

    def get_encryption_key(self):
        """Get the derived encryption key for use in encryption/decryption"""
        if self.encryption_key is None:
            raise ValueError("Not authenticated. Please authenticate first.")
        
        return self.encryption_key

    def change_master_password(self, old_password, new_password):
        """Change the master password"""
        # First authenticate with the old password
        if not self.authenticate(old_password):
            return False
        
        # Then set up the new password
        return self.setup_master_password(new_password)