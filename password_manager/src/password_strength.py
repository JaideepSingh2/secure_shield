import re
import math
import os

class PasswordStrengthChecker:
    def __init__(self):
        # Initialize with an empty list
        self.common_passwords = []
        
        # Load common passwords from file
        self.load_common_passwords()
    
    def load_common_passwords(self):
        """Load common passwords from a file"""
        try:
            # Define the path to the common passwords file
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'common_pass.txt')
            
            # Check if file exists
            if not os.path.exists(file_path):
                print(f"Warning: Common passwords file not found at {file_path}")
                # Fallback to a minimal list
                self.common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
                return
                
            # Read passwords from file
            with open(file_path, 'r') as f:
                self.common_passwords = [line.strip().lower() for line in f if line.strip()]
                
            print(f"Loaded {len(self.common_passwords)} common passwords")
                
        except Exception as e:
            print(f"Error loading common passwords: {str(e)}")
            # Fallback to a minimal list in case of error
            self.common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]

    
    def check_strength(self, password):
        """
        Check the strength of a password and return a score from 0-100
        and a classification (weak, medium, strong, very strong)
        """
        if not password:
            return 0, "Very weak", "No password provided"
        
        # Check if it's a common password
        if password.lower() in self.common_passwords:
            return 5, "Very weak", "This is a commonly used password"
        
        # Basic metrics
        length = len(password)
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # Check for sequential characters
        has_sequential = False
        for i in range(len(password) - 2):
            if (ord(password[i+1]) - ord(password[i]) == 1 and 
                ord(password[i+2]) - ord(password[i+1]) == 1):
                has_sequential = True
                break
        
        # Check for repeated characters
        has_repeated = bool(re.search(r'(.)\1{2,}', password))  # Same char repeated 3+ times
        
        # Calculate entropy (basic estimation)
        charset_size = 0
        if has_uppercase: charset_size += 26
        if has_lowercase: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 33  # Approximate count of special chars
        
        # Shannon entropy formula
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0
        
        # Base score from entropy
        if entropy <= 28:
            score = 20
            category = "Weak"
        elif entropy <= 60:
            score = 40
            category = "Medium"
        elif entropy <= 80:
            score = 60
            category = "Strong"
        else:
            score = 80
            category = "Very strong"
        
        # Adjustments based on other factors
        if has_sequential:
            score -= 10
        if has_repeated:
            score -= 10
        
        # Length bonus
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        
        # Character set bonus
        diversity_score = (has_uppercase + has_lowercase + has_digit + has_special) * 5
        score += diversity_score
        
        # Cap the score at 100
        score = min(100, max(0, score))
        
        # Generate feedback message
        feedback = []
        if length < 8:
            feedback.append("Password is too short")
        if not has_uppercase:
            feedback.append("Add uppercase letters")
        if not has_lowercase:
            feedback.append("Add lowercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_special:
            feedback.append("Add special characters")
        if has_sequential:
            feedback.append("Avoid sequential characters")
        if has_repeated:
            feedback.append("Avoid repeated characters")
        
        feedback_message = ", ".join(feedback) if feedback else "Good password!"
        
        return score, category, feedback_message
    
    def get_strength_description(self, score):
        """Return a description of the password strength based on score"""
        if score < 20:
            return "Very weak", "This password is extremely vulnerable to attacks."
        elif score < 40:
            return "Weak", "This password could be cracked quickly by attackers."
        elif score < 60:
            return "Medium", "This password provides some security but could be stronger."
        elif score < 80:
            return "Strong", "This password would be difficult for attackers to crack."
        else:
            return "Very strong", "This password provides excellent protection."