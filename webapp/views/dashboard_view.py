from flask import Blueprint, render_template
from webapp.views.scan_view import scans_store, scans_index

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/", methods=["GET"])
def dashboard():
    scans = [scans_store[sid] for sid in scans_index]
    kpi = {
        "total_scans": len(scans),
        "high": sum(1 for s in scans if s.get("level") == "HIGH"),
        "mid": sum(1 for s in scans if s.get("level") == "MID"),
        "low": sum(1 for s in scans if s.get("level") == "LOW"),
    }
    recent_high = [s for s in reversed(scans) if s.get("level") == "HIGH"][:10]
    return render_template("dashboard.html", kpi=kpi, recent_high=recent_high)