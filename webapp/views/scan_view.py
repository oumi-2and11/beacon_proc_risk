import uuid
import datetime

from flask import Blueprint, render_template, abort, current_app

from webapp.db import db
from webapp.models import (
    ScanRun, ProcessCatalog, ScanTarget, ScanScore, RuleHit,
    NetBeaconStats, NetRemoteSummary, NetConnection,
)

scan_bp = Blueprint("scan", __name__)


# ---------------------------------------------------------------------------
# 内部辅助：将 ScanRun ORM 对象转为模板所需的字典
# ---------------------------------------------------------------------------
def scan_run_to_dict(run):
    """将 ScanRun 及其关联的第一个 ScanTarget/ScanScore/RuleHit 转为模板兼容字典。"""
    target = run.targets[0] if run.targets else None
    score_obj = target.score if target else None
    hits = []
    if target:
        for h in target.hits:
            if isinstance(h.evidence_json, dict):
                evidence_str = str(h.evidence_json.get("detail", ""))
            elif h.evidence_json:
                evidence_str = str(h.evidence_json)
            else:
                evidence_str = "暂无证据数据"
            hits.append({
                "rule_id": h.rule_id,
                "title": h.title,
                "evidence": evidence_str,
            })
    return {
        "scan_id": run.scan_uuid,
        "created_at": (
            run.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if run.created_at else ""
        ),
        "mode": run.mode,
        "target": target.target_label if target else "",
        "score": score_obj.total_score if score_obj else 0,
        "level": score_obj.level if score_obj else "LOW",
        "hits": hits,
    }


# ---------------------------------------------------------------------------
# 内部辅助：创建真实扫描记录（接入检测流水线）
# ---------------------------------------------------------------------------
def create_scan(target, mode="single"):
    """对目标进程运行完整检测流水线，写入数据库，返回模板兼容字典。"""
    from utils.risk_detector.detector import detect_process, DetectionResult
    from utils.process_collector.collector import sync_process_catalog
    from utils.common.helpers import get_hostname, get_os_info
    from utils.common.constants import APP_VERSION

    now = datetime.datetime.now()

    # 1. 解析 PID
    pid = 0
    if target.startswith("pid:"):
        try:
            pid = int(target[4:])
        except ValueError:
            pass

    # 2. 运行检测流水线
    try:
        result = detect_process(
            pid=pid,
            db_session=db.session,
            sample_window=current_app.config.get("BEACON_SAMPLE_WINDOW", 20),
        )
    except ValueError:
        # 进程不存在，仍创建一条 failed 记录
        run = ScanRun(
            scan_uuid=str(uuid.uuid4()),
            mode=mode,
            status="failed",
            created_at=now,
            finished_at=datetime.datetime.now(),
            host_name=get_hostname(),
            os_info=get_os_info(),
            note=f"无法访问进程 PID={pid}",
        )
        db.session.add(run)
        db.session.commit()
        return scan_run_to_dict(run)

    # 3. 同步进程到 process_catalog
    proc_record = sync_process_catalog(result.process_info, db.session)

    # 4. 写入 ScanRun
    level = result.score.level
    run = ScanRun(
        scan_uuid=str(uuid.uuid4()),
        mode=mode,
        status="finished",
        created_at=now,
        finished_at=datetime.datetime.now(),
        duration_ms=int((datetime.datetime.now() - now).total_seconds() * 1000),
        host_name=get_hostname(),
        os_info=get_os_info(),
        app_version=APP_VERSION,
        target_count=1,
        high_count=1 if level == "HIGH" else 0,
        mid_count=1 if level == "MID" else 0,
        low_count=1 if level == "LOW" else 0,
    )
    db.session.add(run)
    db.session.flush()

    # 5. 写入 ScanTarget
    st = ScanTarget(
        scan_run_id=run.id,
        process_id=proc_record.id,
        target_label=target,
        collected_at=now,
    )
    db.session.add(st)
    db.session.flush()

    # 6. 写入 ScanScore
    ss = ScanScore(
        scan_target_id=st.id,
        total_score=result.score.total_score,
        level=result.score.level,
        score_process=result.score.score_process,
        score_network=result.score.score_network,
        score_memory=result.score.score_memory,
        score_other=result.score.score_other,
        summary_reason=result.score.summary_reason,
    )
    db.session.add(ss)

    # 7. 写入 RuleHit
    for hit in result.hits:
        db.session.add(RuleHit(
            scan_target_id=st.id,
            rule_id=hit.rule_id,
            title=hit.title,
            dimension=hit.dimension,
            score_delta=hit.score_delta,
            evidence_json=hit.evidence,
            created_at=now,
        ))

    # 8. 写入 NetBeaconStats
    if result.beacon_stats:
        bs = result.beacon_stats
        db.session.add(NetBeaconStats(
            scan_target_id=st.id,
            sample_window=bs.sample_window,
            interval_mean_ms=bs.interval_mean_ms,
            interval_std_ms=bs.interval_std_ms,
            interval_cv=bs.interval_cv,
            suspected=bs.suspected,
            jitter_like=bs.jitter_like,
            notes=bs.notes,
        ))

    # 9. 写入 NetRemoteSummary + NetConnection
    for summary in result.remote_summaries:
        db.session.add(NetRemoteSummary(
            scan_target_id=st.id,
            remote_ip=summary.remote_ip,
            remote_port=summary.remote_port,
            protocol=summary.protocol,
            conn_count=summary.conn_count,
            first_seen_at=summary.first_seen_at,
            last_seen_at=summary.last_seen_at,
            risk_hint=summary.risk_hint,
        ))

    for conn in result.connections:
        db.session.add(NetConnection(
            scan_target_id=st.id,
            protocol=conn.protocol,
            local_ip=conn.local_ip,
            local_port=conn.local_port,
            remote_ip=conn.remote_ip,
            remote_port=conn.remote_port,
            state=conn.state,
            seen_at=conn.seen_at,
        ))

    db.session.commit()

    return scan_run_to_dict(run)


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@scan_bp.route("/", methods=["GET"])
def list_scans():
    runs = ScanRun.query.order_by(ScanRun.created_at.desc()).all()
    scans = [scan_run_to_dict(r) for r in runs]
    return render_template("scans.html", scans=scans)


@scan_bp.route("/<scan_id>", methods=["GET"])
def scan_detail(scan_id):
    run = ScanRun.query.filter_by(scan_uuid=scan_id).first()
    if not run:
        abort(404)
    scan = scan_run_to_dict(run)
    return render_template("scan_detail.html", scan=scan)
