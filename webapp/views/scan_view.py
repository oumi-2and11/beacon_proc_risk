from flask import Blueprint, render_template, abort

scan_bp = Blueprint("scan", __name__)

# --- 临时“伪存储”：后续替换为 MySQL ---
scans_store = {}
scans_index = []

def make_fake_scan(target: str, mode: str = "single"):
    # 仅用于把页面逻辑跑通，后续你用真实扫描结果替换
    import uuid, datetime
    scan_id = uuid.uuid4().hex[:10]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    score = 75
    level = "HIGH" if score >= 70 else ("MID" if score >= 40 else "LOW")

    return {
        "scan_id": scan_id,
        "created_at": now,
        "mode": mode,
        "target": target,
        "score": score,
        "level": level,
        "hits": [
            {"rule_id": "PROC-001", "title": "父子进程关系异常（示例）", "evidence": "ppid -> child mismatch"},
            {"rule_id": "NET-101", "title": "疑似 Beaconing 周期性通信（示例）", "evidence": "mu=5.0s, cv=0.12"},
        ],
    }

@scan_bp.route("/", methods=["GET"])
def list_scans():
    scans = [scans_store[sid] for sid in reversed(scans_index)]
    return render_template("scans.html", scans=scans)

@scan_bp.route("/<scan_id>", methods=["GET"])
def scan_detail(scan_id: str):
    scan = scans_store.get(scan_id)
    if not scan:
        abort(404)
    return render_template("scan_detail.html", scan=scan)