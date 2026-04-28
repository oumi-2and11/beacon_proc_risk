from flask import Blueprint, render_template
from sqlalchemy import func

from webapp.db import db
from webapp.models import ScanRun
from webapp.views.scan_view import scan_run_to_dict

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/", methods=["GET"])
def dashboard():
    total_scans = ScanRun.query.count()
    high = db.session.query(func.sum(ScanRun.high_count)).scalar() or 0
    mid = db.session.query(func.sum(ScanRun.mid_count)).scalar() or 0
    low = db.session.query(func.sum(ScanRun.low_count)).scalar() or 0

    kpi = {
        "total_scans": total_scans,
        "high": int(high),
        "mid": int(mid),
        "low": int(low),
    }

    recent_high_runs = (
        ScanRun.query
        .filter(ScanRun.high_count > 0)
        .order_by(ScanRun.created_at.desc())
        .limit(10)
        .all()
    )
    recent_high = [scan_run_to_dict(r) for r in recent_high_runs]

    return render_template("dashboard.html", kpi=kpi, recent_high=recent_high)
