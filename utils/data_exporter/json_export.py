"""增强型 JSON 导出：从 ScanRun ORM 构建完整嵌套字典。"""

from typing import Dict, Any, Optional

from webapp.models import ScanRun


def build_scan_dict(run: ScanRun) -> Dict[str, Any]:
    """将 ScanRun 及其全部关联子表转为完整嵌套字典。

    结构：
    {
      "metadata": { scan_id, mode, created_at, host_name, os_info, app_version },
      "targets": [{
        "process": { pid, name, exe_path, signed_status, ... },
        "score": { total, level, process, network, memory, other, summary_reason },
        "rule_hits": [...],
        "beacon_stats": {...},
        "remote_summaries": [...],
        "connections": [...]
      }],
      "summary": { target_count, high_count, mid_count, low_count }
    }
    """
    metadata = {
        "scan_id": run.scan_uuid,
        "mode": run.mode,
        "status": run.status,
        "created_at": run.created_at.strftime("%Y-%m-%d %H:%M:%S") if run.created_at else None,
        "finished_at": run.finished_at.strftime("%Y-%m-%d %H:%M:%S") if run.finished_at else None,
        "duration_ms": run.duration_ms,
        "host_name": run.host_name,
        "os_info": run.os_info,
        "app_version": run.app_version,
    }

    targets = []
    for st in run.targets:
        # 进程信息
        proc = st.process
        process_data = {}
        if proc:
            process_data = {
                "pid": proc.pid,
                "name": proc.name,
                "exe_path": proc.exe_path,
                "cmdline": proc.cmdline,
                "username": proc.username,
                "ppid": proc.ppid,
                "parent_name": proc.parent_name,
                "is_system": proc.is_system,
                "signed_status": proc.signed_status,
                "path_suspicious": proc.path_suspicious,
                "parent_child_suspicious": proc.parent_child_suspicious,
            }

        # 评分
        score_data = {}
        if st.score:
            score_data = {
                "total": st.score.total_score,
                "level": st.score.level,
                "process": st.score.score_process,
                "network": st.score.score_network,
                "memory": st.score.score_memory,
                "other": st.score.score_other,
                "summary_reason": st.score.summary_reason,
            }

        # 规则命中
        hits_data = []
        for h in st.hits:
            hits_data.append({
                "rule_id": h.rule_id,
                "title": h.title,
                "dimension": h.dimension,
                "score_delta": h.score_delta,
                "evidence": h.evidence_json,
                "created_at": h.created_at.strftime("%Y-%m-%d %H:%M:%S") if h.created_at else None,
            })

        # Beaconing 统计
        beacon_data = {}
        if st.beacon_stats:
            bs = st.beacon_stats
            beacon_data = {
                "sample_window": bs.sample_window,
                "interval_mean_ms": bs.interval_mean_ms,
                "interval_std_ms": bs.interval_std_ms,
                "interval_cv": bs.interval_cv,
                "suspected": bs.suspected,
                "jitter_like": bs.jitter_like,
                "notes": bs.notes,
            }

        # 远端 IP 汇总
        remote_data = []
        for rs in st.remote_summaries:
            remote_data.append({
                "remote_ip": rs.remote_ip,
                "remote_port": rs.remote_port,
                "protocol": rs.protocol,
                "conn_count": rs.conn_count,
                "first_seen_at": rs.first_seen_at.strftime("%Y-%m-%d %H:%M:%S") if rs.first_seen_at else None,
                "last_seen_at": rs.last_seen_at.strftime("%Y-%m-%d %H:%M:%S") if rs.last_seen_at else None,
                "risk_hint": rs.risk_hint,
            })

        # 连接明细
        conn_data = []
        for c in st.connections:
            conn_data.append({
                "protocol": c.protocol,
                "local_ip": c.local_ip,
                "local_port": c.local_port,
                "remote_ip": c.remote_ip,
                "remote_port": c.remote_port,
                "state": c.state,
                "seen_at": c.seen_at.strftime("%Y-%m-%d %H:%M:%S") if c.seen_at else None,
            })

        targets.append({
            "process": process_data,
            "score": score_data,
            "rule_hits": hits_data,
            "beacon_stats": beacon_data,
            "remote_summaries": remote_data,
            "connections": conn_data,
        })

    summary = {
        "target_count": run.target_count,
        "high_count": run.high_count,
        "mid_count": run.mid_count,
        "low_count": run.low_count,
    }

    return {
        "metadata": metadata,
        "targets": targets,
        "summary": summary,
    }
