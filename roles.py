# roles.py
ROLE_MAP = {
1: ("Super Admin", "Full system access", True,
"Super Admin has unrestricted control; may cause security risk if misused."),
2: ("Administrator", "Manage users, settings, and data", False,
"Admin has controlled access; safe if proper password and policies exist."),
3: ("Power User", "Configure and modify some system settings", False,
"Power users have limited admin privileges; low risk."),
4: ("Standard User", "Access and modify own data only", False,
"Standard users have minimal access; generally safe."),
5: ("Guest", "Read-only limited access", True,
"Guest accounts can be risky if not monitored; potential entry point."),
}




def role_access(access_level):
    return ROLE_MAP.get(access_level, ("Unknown", "None", True, "Invalid access level entered."))