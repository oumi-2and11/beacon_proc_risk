from flask import Blueprint, render_template, request, redirect, url_for

process_bp = Blueprint("process", __name__)

# --- 临时“伪存储”：后续你换 MySQL 时，把这里替换为数据库读写即可 ---
# scans_store: scan_id -> scan dict
# scans_index: list of scan_id (按时间倒序/顺序)
from webapp.views.scan_view import scans_store, scans_index, make_fake_scan  # 简化：先跨模块复用

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
def process_detail(pid: int):
    proc = {"pid": pid, "name": "python.exe", "user": "YOU", "path": r"C:\Python\python.exe", "ppid": 1234}

    # 找到“最近一次针对该 PID 的扫描”（示例逻辑）
    latest_scan = None
    for scan_id in reversed(scans_index):
        s = scans_store.get(scan_id)
        if s and s.get("target") == f"pid:{pid}":
            latest_scan = s
            break

    return render_template("process_detail.html", proc=proc, latest_scan=latest_scan)

@process_bp.route("/<int:pid>/scan", methods=["POST"])
def scan_process(pid: int):
    # 这里先生成“假扫描结果”，后续替换为真实检测引擎
    scan = make_fake_scan(target=f"pid:{pid}", mode="single")
    scans_store[scan["scan_id"]] = scan
    scans_index.append(scan["scan_id"])
    return redirect(url_for("scan.scan_detail", scan_id=scan["scan_id"]))