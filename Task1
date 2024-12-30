import string
import re
import math
from collections import Counter

# A list of common weak passwords (this could be expanded or loaded from an external source)
common_passwords = {
    "123456", "password", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin", "password1", "12345"
}

# Check length of password
def check_length(password):
    length = len(password)
    if length < 8:
        return False, "Password should be at least 8 characters long."
    return True, ""

# Check password complexity: includes uppercase, lowercase, digits, and special characters
def check_complexity(password):
    complexity_score = 0
    if re.search(r'[a-z]', password):
        complexity_score += 1
    if re.search(r'[A-Z]', password):
        complexity_score += 1
    if re.search(r'[0-9]', password):
        complexity_score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        complexity_score += 1
    if complexity_score < 3:
        return False, "Password must contain at least 3 of the following: lowercase, uppercase, digits, special characters."
    return True, ""

# Check password entropy (randomness)
def calculate_entropy(password):
    # Count the frequency of each character
    counter = Counter(password)
    # Calculate the number of unique characters
    unique_chars = len(counter)
    # Calculate entropy (base 2)
    entropy = math.log2(unique_chars ** len(password))
    return entropy

# Check if password is too common
def check_common_passwords(password):
    if password.lower() in common_passwords:
        return False, "Password is too common. Please choose a more unique password."
    return True, ""

# Main password strength check function
def check_password_strength(password):
    # 1. Check length
    valid, message = check_length(password)
    if not valid:
        return f"Weak: {message}"

    # 2. Check complexity
    valid, message = check_complexity(password)
    if not valid:
        return f"Weak: {message}"

    # 3. Check if it's a common password
    valid, message = check_common_passwords(password)
    if not valid:
        return f"Weak: {message}"

    # 4. Calculate entropy
    entropy = calculate_entropy(password)
    if entropy < 40:
        return f"Weak: Entropy is too low. Try a more random password."
    elif entropy < 60:
        return f"Moderate: Entropy is moderate. Consider using more characters or special characters for better security."
    else:
        return f"Strong: Password is strong with high entropy."

# Example of usage
if __name__ == "__main__":
    password = input("Enter a password: ")
    strength_message = check_password_strength(password)
    print(strength_message)
