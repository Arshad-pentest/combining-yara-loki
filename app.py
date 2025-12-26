from engines.risk_engine import calculate_risk
from flask import Flask, render_template, request, send_file
import os
import subprocess
import hashlib
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)

# ---------------- CONFIG ----------------
UPLOAD_FOLDER = "uploads"
YARA_RULES_FOLDER = "yara_rules"
LOKI_IOCS_FOLDER = "loki_iocs"
REPORT_FOLDER = "reports"

ENABLE_YARA = True
ENABLE_LOKI = True

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(YARA_RULES_FOLDER, exist_ok=True)
os.makedirs(LOKI_IOCS_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
# --------------------------------------


# ---------------- UTILITIES ----------------
def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_impact(yara_result, loki_result):
    if yara_result and loki_result:
        return "High", "🔴"
    elif yara_result:
        return "Medium", "🟡"
    elif loki_result:
        return "Low", "🟢"
    else:
        return "None", "✅"


def create_pdf(report_path, data):
    c = canvas.Canvas(report_path, pagesize=A4)
    width, height = A4
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Malware Scan Report")

    c.setFont("Helvetica", 11)
    y -= 30
    c.drawString(50, y, f"File Name: {data['filename']}")
    y -= 20
    c.drawString(50, y, f"File Size: {data['size']} bytes")
    y -= 20
    c.drawString(50, y, f"SHA256: {data['sha256']}")
    y -= 20
    c.drawString(50, y, f"Impact Level: {data['impact']}")

    y -= 30
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "YARA Result")
    c.setFont("Helvetica", 10)
    y -= 20
    for line in (data["yara"] or "No YARA matches").split("\n"):
        c.drawString(50, y, line)
        y -= 14

    y -= 20
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "LOKI Result")
    c.setFont("Helvetica", 10)
    y -= 20
    for line in (data["loki"] or "No LOKI alerts").split("\n"):
        c.drawString(50, y, line)
        y -= 14

    c.save()
# ------------------------------------------


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/config")
def config_page():
    return render_template(
        "config.html",
        enable_yara=ENABLE_YARA,
        enable_loki=ENABLE_LOKI
    )


@app.route("/config", methods=["POST"])
def save_config():
    global ENABLE_YARA, ENABLE_LOKI
    ENABLE_YARA = "enable_yara" in request.form
    ENABLE_LOKI = "enable_loki" in request.form
    return render_template(
        "config.html",
        enable_yara=ENABLE_YARA,
        enable_loki=ENABLE_LOKI
    )


@app.route("/upload_yara", methods=["POST"])
def upload_yara_rule():
    file = request.files.get("yara_rule")
    if file:
        file.save(os.path.join(YARA_RULES_FOLDER, file.filename))
    return render_template(
        "config.html",
        enable_yara=ENABLE_YARA,
        enable_loki=ENABLE_LOKI
    )


@app.route("/upload_loki", methods=["POST"])
def upload_loki_ioc():
    file = request.files.get("loki_ioc")
    if file:
        file.save(os.path.join(LOKI_IOCS_FOLDER, file.filename))
    return render_template(
        "config.html",
        enable_yara=ENABLE_YARA,
        enable_loki=ENABLE_LOKI
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file uploaded"

    file = request.files["file"]
    if file.filename == "":
        return "No file selected"

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    size = os.path.getsize(filepath)
    sha256 = calculate_sha256(filepath)

    yara_result = None
    loki_result = None

    if ENABLE_YARA:
        yara_result = subprocess.getoutput(
            f"yara {YARA_RULES_FOLDER} {filepath}"
        )

    if ENABLE_LOKI:
        loki_result = subprocess.getoutput(
            f"loki -p {filepath} --nolog --noindicator"
        )

    impact_level, impact_icon = calculate_impact(yara_result, loki_result)

    pdf_name = f"{file.filename}.pdf"
    pdf_path = os.path.join(REPORT_FOLDER, pdf_name)

    create_pdf(pdf_path, {
        "filename": file.filename,
        "size": size,
        "sha256": sha256,
        "impact": impact_level,
        "yara": yara_result,
        "loki": loki_result
    })

    return render_template(
        "results.html",
        filename=file.filename,
        size=size,
        sha256=sha256,
        yara_matches=yara_result if yara_result else None,
        loki_matches=loki_result if loki_result else None,
        impact=impact_level,
        impact_icon=impact_icon,
        pdf_name=pdf_name
    )


@app.route("/download/<pdf_name>")
def download_pdf(pdf_name):
    return send_file(
        os.path.join(REPORT_FOLDER, pdf_name),
        as_attachment=True
    )
# ----------------------------------------


# ---------------- START SERVER ----------------
import os

app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 5000)),
    debug=False
)
