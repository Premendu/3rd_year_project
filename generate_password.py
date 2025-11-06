# generate_password.py
import secrets
import string

def suggest_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    if length < 4:
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    parts = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+")
    ]
    if length > 4:
        parts.append(''.join(secrets.choice(alphabet) for _ in range(length - 4)))
    pw = list(''.join(parts))
    secrets.SystemRandom().shuffle(pw)
    return ''.join(pw)

if __name__ == "__main__":
    print(suggest_password(12))
