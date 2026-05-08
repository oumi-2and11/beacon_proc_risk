from flask import Blueprint, render_template, request, redirect, url_for, abort, current_app

from webapp.db import db
from webapp.models import ScanRun, ScanTarget, ProcessCatalog
from webapp.views.scan_view import create_scan, scan_run_to_dict
from utils.process_collector import get_process_list, get_process_by_pid

process_bp = Blueprint("process", __name__)


@process_bp.route("/", methods=["GET"])
def list_processes():
    q = request.args.get("q", "").strip()

    process_infos = get_process_list(
        max_processes=current_app.config.get("MAX_PROCESSES", 5000), query=q
    )
    processes = [p.to_dict() for p in process_infos]

    return render_template("processes.html", processes=processes, q=q)


@process_bp.route("/<int:pid>", methods=["GET"])
def process_detail(pid):
    proc_info = get_process_by_pid(pid)
    if proc_info is None:
        abort(404)
    proc = proc_info.to_detail_dict()

    # 从数据库查找"最近一次针对该 PID 的扫描"
    latest_run = (
        ScanRun.query
        .join(ScanTarget, ScanRun.id == ScanTarget.scan_run_id)
        .join(ProcessCatalog, ScanTarget.process_id == ProcessCatalog.id)
        .filter(ProcessCatalog.pid == pid)
        .order_by(ScanRun.created_at.desc())
        .first()
    )
    latest_scan = scan_run_to_dict(latest_run) if latest_run else None

    return render_template("process_detail.html", proc=proc, latest_scan=latest_scan)


@process_bp.route("/<int:pid>/scan", methods=["POST"])
def scan_process(pid):
    # 创建扫描记录并写入数据库
    scan = create_scan(target=f"pid:{pid}", mode="single")
    return redirect(url_for("scan.scan_detail", scan_id=scan["scan_id"]))
