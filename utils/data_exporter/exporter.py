"""统一导出接口：JSON / HTML。"""

from flask import jsonify, Response

from utils.data_exporter.json_export import build_scan_dict
from utils.data_exporter.html_report import generate_html_report


def export_scan_json(run) -> Response:
    """从 ScanRun ORM 对象导出完整嵌套 JSON。"""
    data = build_scan_dict(run)
    return jsonify(data)


def export_scan_html(run) -> Response:
    """从 ScanRun ORM 对象导出独立 HTML 报告。"""
    data = build_scan_dict(run)
    html = generate_html_report(data)
    return Response(html, mimetype="text/html; charset=utf-8")
