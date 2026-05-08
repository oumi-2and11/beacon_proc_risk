from flask import Blueprint, render_template, request, redirect, url_for, flash

from webapp.db import db
from webapp.models import Allowlist

allowlist_bp = Blueprint("allowlist", __name__)

DEFAULT_ALLOWLIST = [
    ("process_name", "svchost.exe", "Windows 服务主机"),
    ("process_name", "csrss.exe", "客户端/服务器运行时子系统"),
    ("process_name", "lsass.exe", "本地安全认证"),
    ("process_name", "services.exe", "服务控制管理器"),
    ("process_name", "winlogon.exe", "Windows 登录"),
    ("process_name", "dwm.exe", "桌面窗口管理器"),
    ("process_name", "explorer.exe", "Windows 资源管理器"),
    ("process_name", "taskhostw.exe", "任务主机"),
    ("process_name", "RuntimeBroker.exe", "运行时代理"),
    ("process_path", "C:\\Windows\\System32\\", "System32 目录"),
]


@allowlist_bp.route("/", methods=["GET"])
def list_allowlist():
    """白名单管理页，首次访问自动填充默认条目。"""
    if Allowlist.query.count() == 0:
        for atype, value, note in DEFAULT_ALLOWLIST:
            db.session.add(Allowlist(type=atype, value=value, note=note, enabled=True))
        db.session.commit()

    entries = Allowlist.query.order_by(Allowlist.type, Allowlist.value).all()
    return render_template("allowlist.html", entries=entries)


@allowlist_bp.route("/add", methods=["POST"])
def add_entry():
    etype = request.form.get("type", "").strip()
    value = request.form.get("value", "").strip()
    note = request.form.get("note", "").strip()

    if not etype or not value:
        flash("类型和值不能为空", "error")
        return redirect(url_for("allowlist.list_allowlist"))

    existing = Allowlist.query.filter_by(type=etype, value=value).first()
    if existing:
        flash("该白名单条目已存在", "error")
        return redirect(url_for("allowlist.list_allowlist"))

    entry = Allowlist(type=etype, value=value, note=note or None, enabled=True)
    db.session.add(entry)
    db.session.commit()
    flash("白名单条目已添加", "success")
    return redirect(url_for("allowlist.list_allowlist"))


@allowlist_bp.route("/<int:entry_id>/toggle", methods=["POST"])
def toggle_entry(entry_id):
    entry = Allowlist.query.get_or_404(entry_id)
    entry.enabled = not entry.enabled
    db.session.commit()
    return redirect(url_for("allowlist.list_allowlist"))


@allowlist_bp.route("/<int:entry_id>/delete", methods=["POST"])
def delete_entry(entry_id):
    entry = Allowlist.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash("白名单条目已删除", "success")
    return redirect(url_for("allowlist.list_allowlist"))


@allowlist_bp.route("/quick-add", methods=["POST"])
def quick_add():
    """从进程详情页快速添加白名单。"""
    add_type = request.form.get("add_type", "process_name")
    value = request.form.get("value", "").strip()
    note = request.form.get("note", "从进程详情页添加")
    pid = request.form.get("pid", "")

    if not value:
        flash("值不能为空", "error")
        return redirect(url_for("process.process_detail", pid=pid))

    existing = Allowlist.query.filter_by(type=add_type, value=value).first()
    if not existing:
        entry = Allowlist(type=add_type, value=value, note=note, enabled=True)
        db.session.add(entry)
        db.session.commit()
        flash(f"已将 {value} 添加到白名单", "success")
    else:
        flash("该条目已在白名单中", "error")

    return redirect(url_for("process.process_detail", pid=pid))
