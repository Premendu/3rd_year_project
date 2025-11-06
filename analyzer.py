# analyzer.py
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~"
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "111111", "abc123", "football", "monkey", "letmein", "shadow",
    "master", "666666", "iloveyou", "welcome", "dragon", "123123",
}
KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def charsets_in_password(pw):
    return {
        'upper': any(c.isupper() for c in pw),
        'lower': any(c.islower() for c in pw),
        'digit': any(c.isdigit() for c in pw),
        'symbol': any(c in SYMBOLS for c in pw),
        'space': any(c.isspace() for c in pw),
    }


def has_sequence(pw, min_len=3):
    p = pw.lower()
    for base in [string.ascii_lowercase, string.digits]:
        for i in range(len(base) - min_len + 1):
            seq = base[i:i + min_len]
            if seq in p or seq[::-1] in p:
                return True
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            seq = row[i:i + min_len]
            if seq in p or seq[::-1] in p:
                return True
    return False


def has_repeated_runs(pw, run_len=3):
    if not pw:
        return False
    count = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            count += 1
            if count >= run_len:
                return True
        else:
            count = 1
    return False


def has_year_like(pw):
    for i in range(len(pw) - 3):
        chunk = pw[i:i + 4]
        if chunk.isdigit():
            val = int(chunk)
            if 1900 <= val <= 2099:
                return True
    return False


def dictionary_word_present(pw):
    p = pw.lower()
    return any(w in p for w in COMMON_PASSWORDS)


def check_password_strength(password, node_role=""):
    reasons = []
    sets = charsets_in_password(password)

    # Basic rules
    if len(password) < 8:
        reasons.append("Password must be at least 8 characters long.")
    if not sets['upper']:
        reasons.append("Password must contain at least one uppercase letter.")
    if not sets['lower']:
        reasons.append("Password must contain at least one lowercase letter.")
    if not sets['digit']:
        reasons.append("Password must contain at least one number.")
    if not sets['symbol']:
        reasons.append("Password must contain at least one special character.")
    if sets['space']:
        reasons.append("Password should not contain spaces.")

    # Advanced pattern checks
    if has_sequence(password):
        reasons.append("Contains easy sequences (e.g., '123', 'abcd', 'qwe').")
    if has_repeated_runs(password):
        reasons.append("Contains repeated characters (e.g., 'aaa', '111').")
    if has_year_like(password):
        reasons.append("Contains a year-like pattern (e.g., 1999, 2024).")
    if dictionary_word_present(password):
        reasons.append("Contains common/blacklisted words.")
    if node_role and node_role.lower() in password.lower():
        reasons.append("Password contains the node role/username. Avoid that.")

    strength = "Password Strong" if not reasons else "Weak Password"
    return strength, reasons


def password_score(password):
    score = 0
    sets = charsets_in_password(password)

    # Composition bonuses
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 10
    if sets['upper']: score += 15
    if sets['lower']: score += 15
    if sets['digit']: score += 15
    if sets['symbol']: score += 25

    # Pattern penalties
    if has_sequence(password): score -= 15
    if has_repeated_runs(password): score -= 10
    if has_year_like(password): score -= 5
    if dictionary_word_present(password): score -= 15

    return max(0, min(100, score))


def classify_risk(access_level, pw_score):
    if access_level in (1, 2):
        if pw_score < 70: return "HIGH"
        elif pw_score < 85: return "MEDIUM"
        else: return "LOW"
    elif access_level == 3:
        return "MEDIUM" if pw_score < 60 else "LOW"
    else:
        return "MEDIUM" if pw_score < 40 else "LOW"