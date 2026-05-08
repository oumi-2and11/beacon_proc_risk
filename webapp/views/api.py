import platform
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, request

from webapp.db import db
from webapp.models import ScanRun, ScanTarget, ProcessCatalog
from utils.process_collector import get_process_list, sync_process_catalog

api_bp = Blueprint("api", __name__)


@api_bp.route("/health")
def health():
    return jsonify({"ok": True})


@api_bp.route("/scan-processes", methods=["POST"])
def scan_processes():
    """采集本机全部进程，写入 process_catalog，创建 ScanRun 记录。"""
    now = datetime.now()

    # 1. 创建 ScanRun
    run = ScanRun(
        scan_uuid=str(uuid.uuid4()),
        mode="full",
        status="running",
        created_at=now,
        host_name=platform.node(),
        os_info=platform.platform(),
    )
    db.session.add(run)
    db.session.flush()

    # 2. 实时采集进程
    try:
        process_infos = get_process_list(max_processes=5000)
    except Exception as e:
        run.status = "failed"
        run.finished_at = datetime.now()
        db.session.commit()
        return jsonify({"ok": False, "error": str(e)}), 500

    # 3. 逐条写库（upsert）
    count = 0
    for pinfo in process_infos:
        try:
            catalog = sync_process_catalog(pinfo, db.session)
            # 创建 ScanTarget 关联
            existing_st = ScanTarget.query.filter_by(
                scan_run_id=run.id, process_id=catalog.id
            ).first()
            if not existing_st:
                st = ScanTarget(
                    scan_run_id=run.id,
                    process_id=catalog.id,
                    target_label=f"pid:{pinfo.pid}",
                    collected_at=now,
                )
                db.session.add(st)
            count += 1
        except Exception:
            continue

    # 4. 更新 ScanRun
    run.status = "finished"
    run.finished_at = datetime.now()
    run.target_count = count
    run.duration_ms = int((datetime.now() - now).total_seconds() * 1000)
    db.session.commit()

    # 5. 返回结果
    return jsonify({
        "ok": True,
        "scan_id": run.scan_uuid,
        "count": count,
        "duration_ms": run.duration_ms,
    })


@api_bp.route("/kpi", methods=["GET"])
def kpi():
    """返回 KPI 数据，供前端局部刷新。"""
    from sqlalchemy import func

    total_scans = ScanRun.query.count()
    high = db.session.query(func.sum(ScanRun.high_count)).scalar() or 0
    mid = db.session.query(func.sum(ScanRun.mid_count)).scalar() or 0
    low = db.session.query(func.sum(ScanRun.low_count)).scalar() or 0
    process_count = ProcessCatalog.query.count()

    return jsonify({
        "total_scans": total_scans,
        "high": int(high),
        "mid": int(mid),
        "low": int(low),
        "process_count": process_count,
    })
