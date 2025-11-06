### FILE: README.md
```markdown
# Password Strength Analyzer (Simple Console)

Files:
- roles.py         : role map and role_access()
- analyzer.py      : password checking functions and scoring
- logger.py        : CSV logging utilities
- generate_password.py : (optional) suggest a secure password
- main.py          : main console UI

## How to run (Windows 11 / any OS with Python 3.8+):
1. Save all files in the same folder.
2. Open PowerShell or Command Prompt and `cd` to that folder.
3. Run: `python main.py`
4. Follow on-screen prompts. Results will be appended to `security_analysis.csv`.

No external libraries required.

## Notes and next steps
- This project intentionally uses simple, readable code (no ML).
- You can extend it by adding a GUI (Tkinter), a web interface (Flask),
  or a browser extension for live password checking.

---

## WEB UI (Flask) — New Files Added

Add to README.md:

```
## Web UI (Flask)

Files added: `web_app.py`, templates folder, static folder.

Install Flask (only dependency):

    pip install flask

Run the app:

    python web_app.py

Open in browser: http://127.0.0.1:5000

Notes:
- The web UI re-uses the same `roles.py`, `analyzer.py`, and `logger.py` modules.
- The app logs each analysis to `security_analysis.csv` (same CSV file used by console version).