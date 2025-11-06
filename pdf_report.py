# pdf_report.py
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import io
from datetime import datetime

def generate_pdf(path, analysis_dict, pie_png_bytes=None):
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    margin = 50
    y = height - margin

    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, y, "Password Analysis Report")
    y -= 24

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Generated: {datetime.now().isoformat()}")
    y -= 20

    def write_line(key, val):
        nonlocal y
        c.setFont("Helvetica-Bold", 10)
        c.drawString(margin, y, f"{key}:")
        c.setFont("Helvetica", 10)
        c.drawString(margin + 120, y, str(val))
        y -= 16

    write_line("Node role", analysis_dict.get("node_role", ""))
    write_line("Role", analysis_dict.get("role", ""))
    write_line("Access level", analysis_dict.get("access_level", ""))
    write_line("Score", f"{analysis_dict.get('score', '')}/100")
    write_line("Risk", analysis_dict.get("risk", ""))
    sha = analysis_dict.get("sha256", "")
    write_line("SHA-256", sha[:32] + ("..." if len(sha) > 32 else ""))

    y -= 6
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Weaknesses / Suggestions:")
    y -= 14
    c.setFont("Helvetica", 10)
    reasons = analysis_dict.get("reasons", [])
    if not reasons:
        c.drawString(margin, y, "None — password looks strong.")
        y -= 14
    else:
        for r in reasons:
            c.drawString(margin + 10, y, "- " + r)
            y -= 12
            if y < margin + 80:
                c.showPage()
                y = height - margin

    y -= 6
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Crack-time estimates:")
    y -= 14
    c.setFont("Helvetica", 10)
    crack_summary = analysis_dict.get("crack_summary", {})
    for label, info in crack_summary.items():
        line = f"{label}: {info.get('readable')}"
        c.drawString(margin + 10, y, line)
        y -= 12
        if y < margin + 80:
            c.showPage()
            y = height - margin

    if pie_png_bytes:
        try:
            img = ImageReader(io.BytesIO(pie_png_bytes))
            img_w = 220
            img_h = 220
            c.drawImage(img, width - margin - img_w, height - margin - img_h - 30, width=img_w, height=img_h)
        except Exception:
            pass

    c.showPage()
    c.save()
