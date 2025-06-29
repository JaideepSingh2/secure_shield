import random
import string
import secrets

class PasswordGenerator:
    def __init__(self):
        self.uppercase_letters = string.ascii_uppercase
        self.lowercase_letters = string.ascii_lowercase
        self.digits = string.digits
        self.special_chars = string.punctuation
    
    def generate_password(self, length=16, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_special=True, exclude_similar=False):
        """Generate a secure random password based on criteria"""
        if length < 4 and (use_uppercase + use_lowercase + use_digits + use_special) > length:
            raise ValueError("Password length too short for the required character types")
        
        # Define character sets based on criteria
        char_sets = []
        required_chars = []
        
        if use_uppercase:
            chars = self.uppercase_letters
            if exclude_similar:
                chars = chars.replace('I', '').replace('O', '')
            char_sets.append(chars)
            required_chars.append(secrets.choice(chars))
            
        if use_lowercase:
            chars = self.lowercase_letters
            if exclude_similar:
                chars = chars.replace('l', '').replace('o', '')
            char_sets.append(chars)
            required_chars.append(secrets.choice(chars))
            
        if use_digits:
            chars = self.digits
            if exclude_similar:
                chars = chars.replace('0', '').replace('1', '')
            char_sets.append(chars)
            required_chars.append(secrets.choice(chars))
            
        if use_special:
            char_sets.append(self.special_chars)
            required_chars.append(secrets.choice(self.special_chars))
        
        if not char_sets:
            raise ValueError("At least one character type must be selected")
        
        # Create a combined character set
        all_chars = ''.join(char_sets)
        
        # Generate the password with at least one character from each required set
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [secrets.choice(all_chars) for _ in range(remaining_length)]
        
        # Shuffle the password to ensure the required characters aren't always at the beginning
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def generate_passphrase(self, num_words=4, delimiter='-'):
        """Generate a passphrase using common words"""
        # This is a small word list for demonstration
        # In a real implementation, you'd use a much larger wordlist
        common_words = [
            "apple", "banana", "carrot", "diamond", "elephant", "forest", "guitar", "house",
            "island", "jacket", "kitchen", "lemon", "mountain", "needle", "orange", "piano",
            "quarter", "river", "sunset", "table", "umbrella", "violet", "window", "xylophone",
            "yellow", "zebra", "airplane", "butterfly", "chocolate", "dinosaur", "eagle", "firefly"
        ]
        
        # Select random words
        selected_words = [secrets.choice(common_words) for _ in range(num_words)]
        
        # Join with delimiter
        return delimiter.join(selected_words)