# web_app.py
import os
import io
from flask import Flask, render_template, request, jsonify, send_file, flash
from roles import role_access
from analyzer import check_password_strength, password_score, classify_risk, sha256_hash, crack_time_summary, COMMON_PASSWORDS
from logger_csv import log_entry, read_all
from generate_password import suggest_password
from pdf_report import generate_pdf

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import Flask

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    recent = []
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

        h = sha256_hash(password)
        crack_summary = crack_time_summary(password)
        # choose offline GPU seconds for numeric logging
        ct_seconds = crack_summary.get('Offline GPU (1e9/s)', {}).get('seconds')

        # breach detection against COMMON_PASSWORDS (exact or as substring)
        breach_flag = any(w == password.lower() or w in password.lower() for w in COMMON_PASSWORDS)

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
            'sha256': h,
            'crack_summary': crack_summary,
            'breach_flag': breach_flag
        }

        # Log to CSV (we do NOT store plaintext password)
        log_entry(node_role, role, access_level, score, risk, breach_flag, h, ct_seconds)

        flash('Analysis complete — results saved to CSV.', 'info')
        recent = list(reversed(read_all()))[:10]
        return render_template('index.html', result=result, recent=recent)

    recent = list(reversed(read_all()))[:10]
    return render_template('index.html', result=result, recent=recent)

@app.route('/generate', methods=['GET'])
def generate_password_route():
    try:
        length = int(request.args.get('len', 12))
    except:
        length = 12
    length = max(6, min(64, length))
    pw = suggest_password(length)
    return jsonify({'password': pw})

@app.route('/summary.png')
def summary_png():
    rows = read_all()
    counts = {'HIGH':0, 'MEDIUM':0, 'LOW':0}
    for r in rows:
        k = (r.get('risk') or '').upper()
        if k in counts:
            counts[k] += 1
    labels = []
    sizes = []
    for k in ['HIGH','MEDIUM','LOW']:
        labels.append(f"{k} ({counts.get(k,0)})")
        sizes.append(counts.get(k,0))
    fig, ax = plt.subplots(figsize=(4,4))
    if sum(sizes) == 0:
        ax.pie([1], labels=["No data"])
    else:
        ax.pie(sizes, labels=labels, autopct=lambda p: ('%1.0f%%' % p) if p>0 else '')
    ax.set_title("Risk distribution")
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    # Build analysis dictionary from form (we expect hidden fields filled)
    node_role = request.form.get('node_role', '')
    role = request.form.get('role', '')
    access_level = request.form.get('access_level', '')
    score = request.form.get('score', '')
    risk = request.form.get('risk', '')
    sha256 = request.form.get('sha256', '')
    reasons = request.form.getlist('reasons')
    # create pie png bytes
    pie_bytes = create_summary_pie_png_bytes()
    analysis = {
        'node_role': node_role,
        'role': role,
        'access_level': access_level,
        'score': score,
        'risk': risk,
        'reasons': reasons,
        'sha256': sha256,
        'crack_summary': {}
    }
    out_path = "password_analysis_report.pdf"
    generate_pdf(out_path, analysis, pie_png_bytes=pie_bytes)
    return send_file(out_path, as_attachment=True, download_name="password_analysis_report.pdf")

@app.route('/dashboard')
def dashboard():
    rows = list(reversed(read_all()))
    return render_template('dashboard.html', rows=rows)

def create_summary_pie_png_bytes():
    rows = read_all()
    counts = {'HIGH':0, 'MEDIUM':0, 'LOW':0}
    for r in rows:
        k = (r.get('risk') or '').upper()
        if k in counts:
            counts[k] += 1
    labels = []
    sizes = []
    for k in ['HIGH','MEDIUM','LOW']:
        labels.append(f"{k} ({counts.get(k,0)})")
        sizes.append(counts.get(k,0))
    fig, ax = plt.subplots(figsize=(4,4))
    if sum(sizes) == 0:
        ax.pie([1], labels=["No data"])
    else:
        ax.pie(sizes, labels=labels, autopct=lambda p: ('%1.0f%%' % p) if p>0 else '')
    ax.set_title("Risk distribution")
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
