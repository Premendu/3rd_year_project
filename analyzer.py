# analyzer.py
import string
import hashlib
import math

SYMBOLS = "!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~"
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "111111", "abc123", "football", "monkey", "letmein", "shadow",
    "master", "666666", "iloveyou", "welcome", "dragon", "123123",
}
KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]

def sha256_hash(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

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
    # Role-based thresholds; higher privileges require stronger passwords
    if access_level in (1, 2):  # Super Admin / Admin
        if pw_score < 70: return "HIGH"
        elif pw_score < 85: return "MEDIUM"
        else: return "LOW"
    elif access_level == 3:    # Power User
        return "MEDIUM" if pw_score < 60 else "LOW"
    else:                      # Standard User / Guest
        return "MEDIUM" if pw_score < 40 else "LOW"

# --- crack time estimation ---
def estimate_charset_size(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in SYMBOLS for c in password): size += len(SYMBOLS)
    if any(ord(c) > 127 for c in password): size += 100
    return max(size, 1)

def human_readable_seconds(sec):
    if sec is None:
        return "Unknown"
    try:
        sec = float(sec)
    except:
        return "Unknown"
    if sec == float('inf'):
        return "Centuries+"
    if sec < 1:
        return f"{sec:.3f} seconds"
    intervals = (
        ('years', 60*60*24*365),
        ('days', 60*60*24),
        ('hours', 60*60),
        ('minutes', 60),
        ('seconds', 1),
    )
    parts = []
    for name, count in intervals:
        val = int(sec // count)
        if val:
            parts.append(f"{val} {name}")
            sec -= val * count
    return ', '.join(parts) if parts else "0 seconds"

def estimate_crack_time_seconds(password, guesses_per_second=1e9):
    L = len(password)
    charset = estimate_charset_size(password)
    # log10 approach to avoid overflow
    log10_combos = L * math.log10(max(charset,1))
    log10_seconds = log10_combos - math.log10(guesses_per_second)
    if log10_seconds > 300:
        return float('inf')
    seconds = 10 ** log10_seconds
    return seconds

def crack_time_summary(password):
    speeds = {
        'Online throttled (100/s)': 100,
        'Online fast (10k/s)': 1e4,
        'Offline GPU (1e9/s)': 1e9,
        'Strong offline (1e12/s)': 1e12,
    }
    summary = {}
    for label, speed in speeds.items():
        secs = estimate_crack_time_seconds(password, guesses_per_second=speed)
        summary[label] = {'seconds': secs if secs != float('inf') else None,
                          'readable': human_readable_seconds(secs)}
    return summary
