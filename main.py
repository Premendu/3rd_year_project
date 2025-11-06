# main.py
from roles import role_access
from analyzer import check_password_strength, password_score, classify_risk
from logger import log_to_csv


def main():
    print("=== Enhanced System Security Risk Analyzer (Console) ===")

    while True:
        cmd = input("\nPress Enter to continue or type 'exit' to quit: ").strip().lower()
        if cmd == "exit":
            print("Exiting... Results saved in 'security_analysis.csv'")
            break

        node_role = input("Enter node's role (root/admin/developer/user/guest): ").strip()
        try:
            access_level = int(input("Enter access level (1–5): "))
            if not (1 <= access_level <= 5):
                print("Invalid access level. Try again.")
                continue
        except ValueError:
            print("Please enter a number between 1 and 5.")
            continue

        password = input("Enter password: ")

        role, permissions, vulnerable, reason = role_access(access_level)
        print(f"\nRole: {role}\nPermissions: {permissions}\nVulnerable: {'Yes' if vulnerable else 'No'}")
        print("Reason:", reason)

        strength, reasons = check_password_strength(password, node_role)
        score = password_score(password)
        risk = classify_risk(access_level, score)

        print(f"\nPassword Strength: {strength}")
        print(f"Password Score: {score}/100")
        print(f"Overall Risk Level: {risk}")

        if reasons:
            print("\nWeaknesses / Suggestions:")
            for r in reasons:
                print(" -", r)
        else:
            print("\nPassword looks strong. Consider enabling MFA for privileged accounts.")

        log_to_csv(node_role, role, access_level, score, risk)
        print("\n--- Entry saved to CSV (security_analysis.csv) ---")


if __name__ == "__main__":
    main()