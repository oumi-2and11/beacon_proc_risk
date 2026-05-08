from flask import Blueprint, render_template, request, redirect, url_for, abort, current_app
from sqlalchemy import or_

from webapp.db import db
from webapp.models import ScanRun, ScanTarget, ProcessCatalog
from webapp.views.scan_view import scan_run_to_dict
from utils.process_collector import get_process_by_pid

process_bp = Blueprint("process", __name__)

PER_PAGE = 50


@process_bp.route("/", methods=["GET"])
def list_processes():
    """从数据库查询进程列表，分页展示。"""
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()

    query = ProcessCatalog.query

    if q:
        # 支持按 PID（精确）或名称（模糊）搜索
        if q.isdigit():
            query = query.filter(ProcessCatalog.pid == int(q))
        else:
            query = query.filter(ProcessCatalog.name.contains(q))

    pagination = (
        query.order_by(ProcessCatalog.last_seen_at.desc())
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )

    # 转为模板需要的字典格式
    processes = []
    for p in pagination.items:
        processes.append({
            "pid": p.pid,
            "name": p.name or "",
            "user": p.username or "",
            "ppid": p.ppid or 0,
            "path": p.exe_path or "",
        })

    # 如果库里没有数据，提示用户先扫描
    empty_hint = (page == 1 and not q and len(processes) == 0)

    return render_template(
        "processes.html",
        processes=processes,
        q=q,
        pagination=pagination,
        empty_hint=empty_hint,
    )


@process_bp.route("/<int:pid>", methods=["GET"])
def process_detail(pid):
    """进程详情页：优先查库，库里没有则实时采集。"""
    # 优先从数据库查
    catalog = ProcessCatalog.query.filter(ProcessCatalog.pid == pid).first()
    if catalog:
        proc = {
            "pid": catalog.pid,
            "name": catalog.name or "",
            "user": catalog.username or "",
            "ppid": catalog.ppid or 0,
            "path": catalog.exe_path or "",
        }
    else:
        # fallback：实时采集
        proc_info = get_process_by_pid(pid)
        if proc_info is None:
            abort(404)
        proc = proc_info.to_detail_dict()

    # 查找最近一次针对该 PID 的扫描
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
    """对单个进程发起扫描。"""
    from webapp.views.scan_view import create_scan
    scan = create_scan(target=f"pid:{pid}", mode="single")
    return redirect(url_for("scan.scan_detail", scan_id=scan["scan_id"]))
