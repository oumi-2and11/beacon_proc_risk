from flask import Blueprint, render_template, abort

from webapp.models import ScanRun
from utils.data_exporter.exporter import export_scan_json as _json, export_scan_html as _html

export_bp = Blueprint("export", __name__)


@export_bp.route("/", methods=["GET"])
def export_home():
    return render_template("export.html")


@export_bp.route("/latest.json", methods=["GET"])
def export_latest_json():
    run = ScanRun.query.order_by(ScanRun.created_at.desc()).first()
    if not run:
        return {"status": "empty", "message": "no scans yet"}, 200
    return _json(run)


@export_bp.route("/scans/<scan_id>.json", methods=["GET"])
def export_scan_json_route(scan_id):
    run = ScanRun.query.filter_by(scan_uuid=scan_id).first()
    if not run:
        abort(404)
    return _json(run)


@export_bp.route("/latest.html", methods=["GET"])
def export_latest_html():
    run = ScanRun.query.order_by(ScanRun.created_at.desc()).first()
    if not run:
        abort(404)
    return _html(run)


@export_bp.route("/scans/<scan_id>.html", methods=["GET"])
def export_scan_html_route(scan_id):
    run = ScanRun.query.filter_by(scan_uuid=scan_id).first()
    if not run:
        abort(404)
    return _html(run)
