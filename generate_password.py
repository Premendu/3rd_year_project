# generate_password.py
import secrets
import string


def suggest_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


if __name__ == "__main__":
    print("Suggested password:", suggest_password(12))