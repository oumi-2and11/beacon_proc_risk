from flask import Blueprint, jsonify, render_template, abort
from webapp.views.scan_view import scans_store, scans_index

export_bp = Blueprint("export", __name__)

@export_bp.route("/", methods=["GET"])
def export_home():
    return render_template("export.html")

@export_bp.route("/latest.json", methods=["GET"])
def export_latest_json():
    if not scans_index:
        return jsonify({"status": "empty", "message": "no scans yet"})
    latest_id = scans_index[-1]
    return jsonify(scans_store.get(latest_id))

@export_bp.route("/scans/<scan_id>.json", methods=["GET"])
def export_scan_json(scan_id: str):
    scan = scans_store.get(scan_id)
    if not scan:
        abort(404)
    return jsonify(scan)