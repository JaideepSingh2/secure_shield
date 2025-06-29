from .auth import MasterPasswordAuth
from .encryption import PasswordEncryption
from .password_store import PasswordStore
from .password_generator import PasswordGenerator
from .password_strength import PasswordStrengthChecker
import os
import getpass
import sys
import pyperclip  # For clipboard functionality

class PasswordManager:
    def __init__(self):
        self.auth = MasterPasswordAuth()
        self.encryption = None
        self.password_store = None
        self.password_generator = PasswordGenerator()
        self.strength_checker = PasswordStrengthChecker()
        self.authenticated = False
    
    def setup(self):
        """Set up the password manager for first-time use"""
        print("Welcome to Password Manager!")
        print("No master password found. Let's set one up.")
        
        while True:
            master_password = getpass.getpass("Enter a master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            
            if master_password == confirm_password:
                self.auth.setup_master_password(master_password)
                print("Master password set up successfully!")
                
                # Initialize encryption with the derived key
                self.encryption = PasswordEncryption(self.auth.get_encryption_key())
                
                # Initialize password store
                self.password_store = PasswordStore(encryption=self.encryption)
                
                self.authenticated = True
                break
            else:
                print("Passwords don't match. Try again.")
    
    def login(self):
        """Authenticate with the master password"""
        print("Welcome back to Password Manager!")
        
        attempts = 0
        while attempts < 3:
            master_password = getpass.getpass("Enter your master password: ")
            
            if self.auth.authenticate(master_password):
                print("Authentication successful!")
                
                # Initialize encryption with the derived key
                self.encryption = PasswordEncryption(self.auth.get_encryption_key())
                
                # Initialize password store
                self.password_store = PasswordStore(encryption=self.encryption)
                
                self.authenticated = True
                break
            else:
                attempts += 1
                remaining = 3 - attempts
                print(f"Incorrect password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
        
        if attempts == 3:
            print("Too many failed attempts. Exiting.")
            sys.exit(1)
    
    def add_password(self):
        """Add a new password entry"""
        site = input("Enter site/app name: ")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        notes = input("Enter optional notes: ")
        
        self.password_store.add_password(site, username, password, notes)
        print(f"Password for {site} saved successfully!")
    
    def get_password(self):
        """Retrieve a password entry"""
        sites = self.password_store.get_all_sites()
        
        if not sites:
            print("No passwords stored yet.")
            return
        
        print("Stored sites:")
        for i, site in enumerate(sites, 1):
            print(f"{i}. {site}")
        
        selection = input("Enter site number or name to retrieve: ")
        
        # Check if selection is a number
        try:
            index = int(selection) - 1
            if 0 <= index < len(sites):
                site = sites[index]
            else:
                print("Invalid selection.")
                return
        except ValueError:
            # Selection is a site name
            site = selection
        
        entry = self.password_store.get_password(site)
        
        if entry:
            print(f"\nSite: {site}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
        else:
            print(f"No entry found for {site}")
    
    def delete_password(self):
        """Delete a password entry"""
        sites = self.password_store.get_all_sites()
        
        if not sites:
            print("No passwords stored yet.")
            return
        
        print("Stored sites:")
        for i, site in enumerate(sites, 1):
            print(f"{i}. {site}")
        
        selection = input("Enter site number or name to delete: ")
        
        # Check if selection is a number
        try:
            index = int(selection) - 1
            if 0 <= index < len(sites):
                site = sites[index]
            else:
                print("Invalid selection.")
                return
        except ValueError:
            # Selection is a site name
            site = selection
        
        confirm = input(f"Are you sure you want to delete the entry for {site}? (y/n): ")
        
        if confirm.lower() == 'y':
            if self.password_store.delete_password(site):
                print(f"Entry for {site} deleted successfully!")
            else:
                print(f"No entry found for {site}")
    
    def generate_password(self):
        """Generate a secure password based on user preferences"""
        print("\nPassword Generator")
        try:
            length = int(input("Password length (8-64) [16]: ") or "16")
            length = max(8, min(64, length))  # Ensure length is between 8 and 64
        except ValueError:
            length = 16
            print("Invalid input. Using default length of 16.")
        
        use_uppercase = input("Include uppercase letters? (y/n) [y]: ").lower() != 'n'
        use_lowercase = input("Include lowercase letters? (y/n) [y]: ").lower() != 'n'
        use_digits = input("Include numbers? (y/n) [y]: ").lower() != 'n'
        use_special = input("Include special characters? (y/n) [y]: ").lower() != 'n'
        exclude_similar = input("Exclude similar characters (I, l, 1, O, 0)? (y/n) [n]: ").lower() == 'y'
        
        try:
            password = self.password_generator.generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                exclude_similar=exclude_similar
            )
            
            print(f"\nGenerated password: {password}")
            
            # Check strength
            score, category, feedback = self.strength_checker.check_strength(password)
            print(f"Password strength: {category} ({score}/100)")
            print(f"Feedback: {feedback}")
            
            # Copy to clipboard option
            if input("\nCopy to clipboard? (y/n) [y]: ").lower() != 'n':
                try:
                    pyperclip.copy(password)
                    print("Password copied to clipboard.")
                except:
                    print("Could not copy to clipboard. Please install pyperclip: pip install pyperclip")
            
            # Save password option
            if input("Save this password? (y/n) [n]: ").lower() == 'y':
                site = input("Enter site/app name: ")
                username = input("Enter username: ")
                notes = input("Enter optional notes: ")
                
                self.password_store.add_password(site, username, password, notes)
                print(f"Password for {site} saved successfully!")
                
        except Exception as e:
            print(f"Error generating password: {str(e)}")
    
    def check_password_strength(self):
        """Check the strength of a user-provided password"""
        print("\nPassword Strength Checker")
        password = getpass.getpass("Enter password to check: ")
        
        score, category, feedback = self.strength_checker.check_strength(password)
        
        print(f"\nPassword strength: {category} ({score}/100)")
        print(f"Feedback: {feedback}")
    
    def run(self):
        """Run the password manager application"""
        if not self.auth.is_configured():
            self.setup()
        else:
            self.login()
        
        while self.authenticated:
            print("\nPassword Manager")
            print("1. Add/Update Password")
            print("2. Get Password")
            print("3. Delete Password")
            print("4. List All Sites")
            print("5. Generate Password")
            print("6. Check Password Strength")
            print("7. Exit")
            
            choice = input("Enter your choice (1-7): ")
            
            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.get_password()
            elif choice == '3':
                self.delete_password()
            elif choice == '4':
                sites = self.password_store.get_all_sites()
                if sites:
                    print("\nStored sites:")
                    for site in sites:
                        print(f"- {site}")
                else:
                    print("No passwords stored yet.")
            elif choice == '5':
                self.generate_password()
            elif choice == '6':
                self.check_password_strength()
            elif choice == '7':
                print("Exiting Password Manager.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.run()