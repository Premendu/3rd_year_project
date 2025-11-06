# web_app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from roles import role_access
from analyzer import check_password_strength, password_score, classify_risk
from logger import log_to_csv

app = Flask(__name__)
app.secret_key = 'dev-secret'

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        node_role = request.form.get('node_role', '').strip()
        try:
            access_level = int(request.form.get('access_level', '1'))
        except ValueError:
            access_level = 1
        password = request.form.get('password', '')

        role, permissions, vulnerable, reason = role_access(access_level)
        strength, reasons = check_password_strength(password, node_role)
        score = password_score(password)
        risk = classify_risk(access_level, score)

        result = {
            'node_role': node_role,
            'role': role,
            'permissions': permissions,
            'vulnerable': vulnerable,
            'reason': reason,
            'strength': strength,
            'reasons': reasons,
            'score': score,
            'risk': risk,
        }

        # Log the check
        log_to_csv(node_role, role, access_level, score, risk)

        # flash a small message
        flash('Analysis complete — saved to CSV.', 'info')

    return render_template('index.html', result=result)

if __name__ == '__main__':
    # When running locally you can still run with: python web_app.py
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)