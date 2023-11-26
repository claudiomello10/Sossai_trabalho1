import hashlib


def compare_passwords():
    with open("password.txt", "r") as password_file:
        password = password_file.read().strip()

    with open("encryptedPassword.txt", "r") as encrypted_password_file:
        encrypted_password = encrypted_password_file.read().strip()

    # Encrypt the password using hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    return hashed_password == encrypted_password
