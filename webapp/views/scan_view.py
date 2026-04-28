import uuid
import datetime

from flask import Blueprint, render_template, abort

from webapp.db import db
from webapp.models import (
    ScanRun, ProcessCatalog, ScanTarget, ScanScore, RuleHit
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
                evidence_str = h.rule_id
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
# 内部辅助：创建一条"示例扫描"记录并写入数据库
# ---------------------------------------------------------------------------
def create_scan(target, mode="single"):
    """
    生成一条示例扫描记录写入数据库，返回模板兼容字典。
    后续替换为真实检测引擎时，只需修改此函数内部逻辑。
    """
    now = datetime.datetime.now()
    score = 75
    level = "HIGH" if score >= 70 else ("MID" if score >= 40 else "LOW")

    # 解析 PID
    pid = 0
    if target.startswith("pid:"):
        try:
            pid = int(target[4:])
        except ValueError:
            pass

    # process_catalog：每次扫描新建一条进程快照（以时间戳区分）
    process_key = f"{pid}:{int(now.timestamp())}"
    proc = ProcessCatalog(
        pid=pid,
        process_key=process_key,
        name=f"process_{pid}" if pid else "unknown",
        first_seen_at=now,
        last_seen_at=now,
    )
    db.session.add(proc)
    db.session.flush()  # 获取 proc.id

    # scan_runs
    run = ScanRun(
        scan_uuid=str(uuid.uuid4()),
        mode=mode,
        status="finished",
        created_at=now,
        finished_at=now,
        target_count=1,
        high_count=1 if level == "HIGH" else 0,
        mid_count=1 if level == "MID" else 0,
        low_count=1 if level == "LOW" else 0,
    )
    db.session.add(run)
    db.session.flush()  # 获取 run.id

    # scan_targets
    st = ScanTarget(
        scan_run_id=run.id,
        process_id=proc.id,
        target_label=target,
        collected_at=now,
    )
    db.session.add(st)
    db.session.flush()  # 获取 st.id

    # scan_scores
    ss = ScanScore(
        scan_target_id=st.id,
        total_score=score,
        level=level,
        score_process=40,
        score_network=35,
        summary_reason="父子进程关系异常 + 疑似 Beaconing（示例）",
    )
    db.session.add(ss)

    # rule_hits（示例规则命中）
    hits_data = [
        {
            "rule_id": "PROC-001",
            "title": "父子进程关系异常（示例）",
            "dimension": "process",
            "score_delta": 20,
            "evidence_json": {"detail": "ppid -> child mismatch"},
        },
        {
            "rule_id": "NET-101",
            "title": "疑似 Beaconing 周期性通信（示例）",
            "dimension": "network",
            "score_delta": 35,
            "evidence_json": {"detail": "mu=5.0s, cv=0.12"},
        },
    ]
    for h in hits_data:
        db.session.add(RuleHit(
            scan_target_id=st.id,
            rule_id=h["rule_id"],
            title=h["title"],
            dimension=h["dimension"],
            score_delta=h["score_delta"],
            evidence_json=h["evidence_json"],
            created_at=now,
        ))

    db.session.commit()

    return {
        "scan_id": run.scan_uuid,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": mode,
        "target": target,
        "score": score,
        "level": level,
        "hits": [
            {
                "rule_id": h["rule_id"],
                "title": h["title"],
                "evidence": h["evidence_json"]["detail"],
            }
            for h in hits_data
        ],
    }


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
