from flask import Blueprint, render_template, request, redirect, url_for, abort
from sqlalchemy import or_

from webapp.db import db
from webapp.models import ScanRun, ScanTarget, ProcessCatalog, Allowlist
from webapp.views.scan_view import scan_run_to_dict
from utils.process_collector import get_process_by_pid
from utils.common.validators import is_allowed

process_bp = Blueprint("process", __name__)

PER_PAGE = 50


def _get_allowlisted_process_ids(allowlist_entries):
    """获取匹配白名单的 ProcessCatalog ID 列表。"""
    ids = []
    all_procs = ProcessCatalog.query.all()
    for p in all_procs:
        pinfo = {"name": p.name, "exe_path": p.exe_path or ""}
        if is_allowed(pinfo, allowlist_entries):
            ids.append(p.id)
    return ids


def _count_suspicious():
    """非「系统+已签名」的进程数。"""
    return ProcessCatalog.query.filter(
        ~db.and_(ProcessCatalog.is_system == True, ProcessCatalog.signed_status == "signed")
    ).count()


def _count_high_risk():
    """有明确风险特征的进程数。"""
    return ProcessCatalog.query.filter(
        or_(
            ProcessCatalog.path_suspicious == True,
            ProcessCatalog.parent_child_suspicious == True,
            ProcessCatalog.signed_status == "unsigned",
            ProcessCatalog.signed_status == "invalid",
        )
    ).count()


@process_bp.route("/", methods=["GET"])
def list_processes():
    """从数据库查询进程列表，支持风险过滤。"""
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()
    filter_tab = request.args.get("filter", "suspicious")

    query = ProcessCatalog.query

    # 搜索
    if q:
        if q.isdigit():
            query = query.filter(ProcessCatalog.pid == int(q))
        else:
            query = query.filter(ProcessCatalog.name.contains(q))

    # 风险过滤
    if filter_tab == "suspicious":
        query = query.filter(
            ~db.and_(ProcessCatalog.is_system == True, ProcessCatalog.signed_status == "signed")
        )
        # 排除白名单进程
        allowlist_entries = Allowlist.query.filter_by(enabled=True).all()
        allowlisted_ids = _get_allowlisted_process_ids(allowlist_entries)
        if allowlisted_ids:
            query = query.filter(~ProcessCatalog.id.in_(allowlisted_ids))

    elif filter_tab == "high_risk":
        query = query.filter(
            or_(
                ProcessCatalog.path_suspicious == True,
                ProcessCatalog.parent_child_suspicious == True,
                ProcessCatalog.signed_status == "unsigned",
                ProcessCatalog.signed_status == "invalid",
            )
        )

    # 排序：风险进程优先
    pagination = (
        query.order_by(
            ProcessCatalog.path_suspicious.desc(),
            ProcessCatalog.parent_child_suspicious.desc(),
            ProcessCatalog.last_seen_at.desc(),
        )
        .paginate(page=page, per_page=PER_PAGE, error_out=False)
    )

    processes = []
    for p in pagination.items:
        processes.append({
            "pid": p.pid,
            "name": p.name or "",
            "user": p.username or "",
            "ppid": p.ppid or 0,
            "path": p.exe_path or "",
            "is_system": p.is_system,
            "signed_status": p.signed_status,
            "path_suspicious": p.path_suspicious,
            "parent_child_suspicious": p.parent_child_suspicious,
        })

    empty_hint = (page == 1 and not q and len(processes) == 0)

    # 各 Tab 计数
    total_count = ProcessCatalog.query.count()
    suspicious_count = _count_suspicious()
    high_risk_count = _count_high_risk()

    return render_template(
        "processes.html",
        processes=processes,
        q=q,
        filter_tab=filter_tab,
        pagination=pagination,
        empty_hint=empty_hint,
        total_count=total_count,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
    )


@process_bp.route("/<int:pid>", methods=["GET"])
def process_detail(pid):
    """进程详情页：优先查库，库里没有则实时采集。"""
    catalog = ProcessCatalog.query.filter(ProcessCatalog.pid == pid).first()
    if catalog:
        proc = {
            "pid": catalog.pid,
            "name": catalog.name or "",
            "user": catalog.username or "",
            "ppid": catalog.ppid or 0,
            "path": catalog.exe_path or "",
            "is_system": catalog.is_system,
            "signed_status": catalog.signed_status,
            "path_suspicious": catalog.path_suspicious,
            "parent_child_suspicious": catalog.parent_child_suspicious,
        }
    else:
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
