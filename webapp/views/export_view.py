from flask import Blueprint, jsonify, render_template, abort

from webapp.models import ScanRun
from webapp.views.scan_view import scan_run_to_dict

export_bp = Blueprint("export", __name__)


@export_bp.route("/", methods=["GET"])
def export_home():
    return render_template("export.html")


@export_bp.route("/latest.json", methods=["GET"])
def export_latest_json():
    run = ScanRun.query.order_by(ScanRun.created_at.desc()).first()
    if not run:
        return jsonify({"status": "empty", "message": "no scans yet"})
    return jsonify(scan_run_to_dict(run))


@export_bp.route("/scans/<scan_id>.json", methods=["GET"])
def export_scan_json(scan_id):
    run = ScanRun.query.filter_by(scan_uuid=scan_id).first()
    if not run:
        abort(404)
    return jsonify(scan_run_to_dict(run))
