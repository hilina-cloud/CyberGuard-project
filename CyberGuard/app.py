import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime
from flask import Flask, render_template, request, send_file, session, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "change-this-local-demo-key-before-any-real-deployment"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit

from detector import SAMPLE_LOG, analyze_text

current_log_text = SAMPLE_LOG
current_source_name = "Built-in demonstration sample"

@app.route("/", methods=["GET", "POST"])
def index():
    global current_log_text, current_source_name
    if request.method == "POST":
        action = request.form.get("action")
        if action == "sample":
            current_log_text = SAMPLE_LOG
            current_source_name = "Built-in demonstration sample"
            flash("Sample data loaded.")
            return redirect(url_for("index"))
        if action == "upload":
            uploaded = request.files.get("logfile")
            if not uploaded or not uploaded.filename:
                flash("Choose a log file first.")
                return redirect(url_for("index"))
            filename = secure_filename(uploaded.filename)
            if not filename:
                flash("The filename is not valid.")
                return redirect(url_for("index"))
            raw = uploaded.stream.read(app.config["MAX_CONTENT_LENGTH"] + 1)
            if len(raw) > app.config["MAX_CONTENT_LENGTH"]:
                flash("File is too large. Maximum upload size is 2 MB.")
                return redirect(url_for("index"))
            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                flash("Could not read this file as text.")
                return redirect(url_for("index"))
            current_log_text = content
            current_source_name = filename
            flash(f"Loaded {filename}. Analysis updated.")
            return redirect(url_for("index"))

    result = analyze_text(current_log_text)
    severity_filter = request.args.get("severity", "ALL").upper()
    event_filter = request.args.get("event", "ALL")
    events = result["events"]
    if severity_filter in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        events = [e for e in events if e["severity"] == severity_filter]
    if event_filter != "ALL":
        events = [e for e in events if e["event"] == event_filter]
    return render_template(
        "index.html", result=result, events=events,
        severity_filter=severity_filter, event_filter=event_filter,
        source_name=current_source_name
    )

@app.route("/export.csv")
def export_csv():
    result = analyze_text(current_log_text)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["severity", "title", "source", "count", "description"])
    writer.writeheader()
    writer.writerows(result["alerts"])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="cyberguard_alerts.csv")

if __name__ == "__main__":
    
    app.run(host="127.0.0.1", port=5000, debug=False)
