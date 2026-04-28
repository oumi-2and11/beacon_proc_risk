from flask import Blueprint, render_template, request, redirect, url_for

from webapp.db import db
from webapp.models import ScanRun, ScanTarget, ProcessCatalog
from webapp.views.scan_view import create_scan, scan_run_to_dict

process_bp = Blueprint("process", __name__)


@process_bp.route("/", methods=["GET"])
def list_processes():
    q = request.args.get("q", "").strip()

    processes = [
        {"pid": 1234, "name": "explorer.exe", "user": "YOU", "path": r"C:\Windows\explorer.exe", "ppid": 1000},
        {"pid": 2345, "name": "python.exe", "user": "YOU", "path": r"C:\Python\python.exe", "ppid": 1234},
    ]

    if q:
        processes = [p for p in processes if q.lower() in p["name"].lower() or q == str(p["pid"])]

    return render_template("processes.html", processes=processes, q=q)


@process_bp.route("/<int:pid>", methods=["GET"])
def process_detail(pid):
    proc = {"pid": pid, "name": "python.exe", "user": "YOU", "path": r"C:\Python\python.exe", "ppid": 1234}

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
