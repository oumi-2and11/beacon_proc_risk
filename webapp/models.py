"""
webapp/models.py
SQLAlchemy 数据模型，对应 beacon_proc_risk 数据库的 10 张核心表。
建表顺序与外键依赖见 项目文档/数据库表设计.md。
"""
import uuid
from datetime import datetime
from webapp.db import db


# ---------------------------------------------------------------------------
# 1. rules — 规则字典表（无外键依赖）
# ---------------------------------------------------------------------------
class Rule(db.Model):
    __tablename__ = "rules"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    rule_id = db.Column(db.String(32), unique=True, nullable=False)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    dimension = db.Column(
        db.Enum("process", "network", "memory", "other"), nullable=False
    )
    default_weight = db.Column(db.Integer, nullable=False, default=10)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<Rule {self.rule_id}>"


# ---------------------------------------------------------------------------
# 2. allowlist — 白名单表（无外键依赖）
# ---------------------------------------------------------------------------
class Allowlist(db.Model):
    __tablename__ = "allowlist"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    type = db.Column(
        db.Enum("process_path", "process_name", "remote_ip", "rule_id"),
        nullable=False,
    )
    value = db.Column(db.String(512), nullable=False)
    note = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.utcnow()
    )

    def __repr__(self):
        return f"<Allowlist {self.type}:{self.value}>"


# ---------------------------------------------------------------------------
# 3. scan_runs — 扫描任务表（无外键依赖）
# ---------------------------------------------------------------------------
class ScanRun(db.Model):
    __tablename__ = "scan_runs"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_uuid = db.Column(
        db.String(36), unique=True, nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
    mode = db.Column(
        db.Enum("single", "multi", "full", "manual"),
        nullable=False, default="single",
    )
    status = db.Column(
        db.Enum("queued", "running", "finished", "failed"),
        nullable=False, default="finished",
    )
    requested_by = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow())
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    host_name = db.Column(db.String(128), nullable=True)
    os_info = db.Column(db.String(128), nullable=True)
    app_version = db.Column(db.String(32), nullable=True)
    target_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    mid_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    note = db.Column(db.String(255), nullable=True)

    targets = db.relationship(
        "ScanTarget", back_populates="scan_run", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<ScanRun {self.scan_uuid} mode={self.mode}>"


# ---------------------------------------------------------------------------
# 4. process_catalog — 进程实例档案表（无外键依赖）
# ---------------------------------------------------------------------------
class ProcessCatalog(db.Model):
    __tablename__ = "process_catalog"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    pid = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    process_key = db.Column(db.String(128), unique=True, nullable=False)
    name = db.Column(db.String(260), nullable=True)
    exe_path = db.Column(db.Text, nullable=True)
    cmdline = db.Column(db.Text, nullable=True)
    username = db.Column(db.String(128), nullable=True)
    ppid = db.Column(db.Integer, nullable=True)
    parent_name = db.Column(db.String(260), nullable=True)
    is_system = db.Column(db.Boolean, nullable=False, default=False)
    signed_status = db.Column(
        db.Enum("unknown", "signed", "unsigned", "invalid"),
        nullable=False, default="unknown",
    )
    first_seen_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.utcnow()
    )
    last_seen_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow()
    )

    scan_targets = db.relationship("ScanTarget", back_populates="process")

    def __repr__(self):
        return f"<ProcessCatalog pid={self.pid} key={self.process_key}>"


# ---------------------------------------------------------------------------
# 5. scan_targets — 扫描目标关联表（依赖 scan_runs、process_catalog）
# ---------------------------------------------------------------------------
class ScanTarget(db.Model):
    __tablename__ = "scan_targets"
    __table_args__ = (
        db.UniqueConstraint("scan_run_id", "process_id", name="uq_scan_target"),
    )

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_run_id = db.Column(
        db.BigInteger, db.ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    process_id = db.Column(
        db.BigInteger, db.ForeignKey("process_catalog.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_label = db.Column(db.String(64), nullable=True)
    collected_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.utcnow()
    )

    scan_run = db.relationship("ScanRun", back_populates="targets")
    process = db.relationship("ProcessCatalog", back_populates="scan_targets")
    score = db.relationship(
        "ScanScore", back_populates="scan_target",
        uselist=False, cascade="all, delete-orphan",
    )
    hits = db.relationship(
        "RuleHit", back_populates="scan_target", cascade="all, delete-orphan"
    )
    beacon_stats = db.relationship(
        "NetBeaconStats", back_populates="scan_target",
        uselist=False, cascade="all, delete-orphan",
    )
    remote_summaries = db.relationship(
        "NetRemoteSummary", back_populates="scan_target",
        cascade="all, delete-orphan",
    )
    connections = db.relationship(
        "NetConnection", back_populates="scan_target",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<ScanTarget scan={self.scan_run_id} proc={self.process_id}>"


# ---------------------------------------------------------------------------
# 6. scan_scores — 评分汇总表（依赖 scan_targets，1:1）
# ---------------------------------------------------------------------------
class ScanScore(db.Model):
    __tablename__ = "scan_scores"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_target_id = db.Column(
        db.BigInteger,
        db.ForeignKey("scan_targets.id", ondelete="CASCADE"),
        unique=True, nullable=False,
    )
    total_score = db.Column(db.Integer, nullable=False)
    level = db.Column(
        db.Enum("LOW", "MID", "HIGH"), nullable=False
    )
    score_process = db.Column(db.Integer, nullable=False, default=0)
    score_network = db.Column(db.Integer, nullable=False, default=0)
    score_memory = db.Column(db.Integer, nullable=False, default=0)
    score_other = db.Column(db.Integer, nullable=False, default=0)
    summary_reason = db.Column(db.String(255), nullable=True)

    scan_target = db.relationship("ScanTarget", back_populates="score")

    def __repr__(self):
        return f"<ScanScore target={self.scan_target_id} score={self.total_score} {self.level}>"


# ---------------------------------------------------------------------------
# 7. rule_hits — 规则命中记录表（依赖 scan_targets）
# ---------------------------------------------------------------------------
class RuleHit(db.Model):
    __tablename__ = "rule_hits"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_target_id = db.Column(
        db.BigInteger,
        db.ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id = db.Column(db.String(32), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    dimension = db.Column(
        db.Enum("process", "network", "memory", "other"), nullable=False
    )
    score_delta = db.Column(db.Integer, nullable=False, default=0)
    evidence_json = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow())

    scan_target = db.relationship("ScanTarget", back_populates="hits")

    def __repr__(self):
        return f"<RuleHit {self.rule_id} target={self.scan_target_id}>"


# ---------------------------------------------------------------------------
# 8. net_beacon_stats — Beaconing 统计表（依赖 scan_targets，1:1）
# ---------------------------------------------------------------------------
class NetBeaconStats(db.Model):
    __tablename__ = "net_beacon_stats"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_target_id = db.Column(
        db.BigInteger,
        db.ForeignKey("scan_targets.id", ondelete="CASCADE"),
        unique=True, nullable=False,
    )
    sample_window = db.Column(db.Integer, nullable=False, default=0)
    interval_mean_ms = db.Column(db.Float, nullable=True)
    interval_std_ms = db.Column(db.Float, nullable=True)
    interval_cv = db.Column(db.Float, nullable=True)
    suspected = db.Column(db.Boolean, nullable=False, default=False)
    jitter_like = db.Column(db.Boolean, nullable=False, default=False)
    notes = db.Column(db.String(255), nullable=True)

    scan_target = db.relationship("ScanTarget", back_populates="beacon_stats")

    def __repr__(self):
        return f"<NetBeaconStats target={self.scan_target_id} suspected={self.suspected}>"


# ---------------------------------------------------------------------------
# 9. net_remote_summary — 远端 IP 汇总表（依赖 scan_targets）
# ---------------------------------------------------------------------------
class NetRemoteSummary(db.Model):
    __tablename__ = "net_remote_summary"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_target_id = db.Column(
        db.BigInteger,
        db.ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    remote_ip = db.Column(db.String(45), nullable=False)
    remote_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(
        db.Enum("TCP", "UDP", "UNKNOWN"), nullable=False, default="TCP"
    )
    conn_count = db.Column(db.Integer, nullable=False, default=0)
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    total_duration_ms = db.Column(db.BigInteger, nullable=True)
    risk_hint = db.Column(db.String(128), nullable=True)

    scan_target = db.relationship("ScanTarget", back_populates="remote_summaries")

    def __repr__(self):
        return f"<NetRemoteSummary {self.remote_ip} target={self.scan_target_id}>"


# ---------------------------------------------------------------------------
# 10. net_connections — 连接明细表（依赖 scan_targets）
# ---------------------------------------------------------------------------
class NetConnection(db.Model):
    __tablename__ = "net_connections"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    scan_target_id = db.Column(
        db.BigInteger,
        db.ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    protocol = db.Column(
        db.Enum("TCP", "UDP", "UNKNOWN"), nullable=False, default="TCP"
    )
    local_ip = db.Column(db.String(45), nullable=True)
    local_port = db.Column(db.Integer, nullable=True)
    remote_ip = db.Column(db.String(45), nullable=True)
    remote_port = db.Column(db.Integer, nullable=True)
    state = db.Column(db.String(32), nullable=True)
    seen_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow())

    scan_target = db.relationship("ScanTarget", back_populates="connections")

    def __repr__(self):
        return f"<NetConnection {self.remote_ip}:{self.remote_port} target={self.scan_target_id}>"
