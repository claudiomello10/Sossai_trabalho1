import hashlib

# Read the password from password.txt
with open("password.txt", "r") as file:
    password = file.read().strip()

# Encrypt the password using hashlib
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# Save the encrypted password in encryptedPassword.txt
with open("encryptedPassword.txt", "w") as file:
    file.write(hashed_password)
