import hashlib
import sys


def compare_passwords(password, encrypted_password):
    # Encrypt the password using hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    return hashed_password == encrypted_password


def main():
    with open("password.txt", "r") as password_file:
        password = password_file.read().strip()

    with open("encryptedPassword.txt", "r") as encrypted_password_file:
        encrypted_password = encrypted_password_file.read().strip()

    return compare_passwords(password, encrypted_password)


if __name__ == "__main__":
    result = main()
    sys.exit(0 if result else 1)
