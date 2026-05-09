"""独立 HTML 报告生成：内联 CSS，可直接在浏览器打印/保存 PDF。"""

from typing import Dict, Any


def _build_remote_section(remote_rows: str) -> str:
    if not remote_rows:
        return ""
    return (
        '<div class="section"><h3>远端 IP 汇总</h3>'
        '<table class="data-table"><thead><tr>'
        '<th>IP</th><th>端口</th><th>协议</th><th>连接数</th><th>风险提示</th>'
        '</tr></thead><tbody>'
        + remote_rows +
        '</tbody></table></div>'
    )


def _build_conn_section(conn_rows: str) -> str:
    if not conn_rows:
        return ""
    return (
        '<div class="section"><h3>连接明细</h3>'
        '<table class="data-table"><thead><tr>'
        '<th>协议</th><th>本地地址</th><th>远端地址</th><th>状态</th>'
        '</tr></thead><tbody>'
        + conn_rows +
        '</tbody></table></div>'
    )


def generate_html_report(scan_data: Dict[str, Any]) -> str:
    """从 build_scan_dict() 返回的字典生成完整独立 HTML 报告。"""

    meta = scan_data.get("metadata", {})
    summary = scan_data.get("summary", {})
    targets = scan_data.get("targets", [])

    # 构建目标行 HTML
    targets_html = ""
    for i, t in enumerate(targets, 1):
        proc = t.get("process", {})
        score = t.get("score", {})
        hits = t.get("rule_hits", [])
        beacon = t.get("beacon_stats", {})
        remotes = t.get("remote_summaries", [])
        conns = t.get("connections", [])

        level = score.get("level", "LOW")
        level_class = level.lower()
        total = score.get("total", 0)

        # 规则命中表行
        hits_rows = ""
        for h in hits:
            evidence_str = ""
            ev = h.get("evidence")
            if isinstance(ev, dict):
                evidence_str = ev.get("detail", str(ev))
            elif ev:
                evidence_str = str(ev)
            hits_rows += f"""<tr>
              <td class="mono">{h.get('rule_id', '')}</td>
              <td>{h.get('title', '')}</td>
              <td>{h.get('dimension', '')}</td>
              <td class="mono">{h.get('score_delta', 0)}</td>
              <td class="mono small">{evidence_str}</td>
            </tr>"""

        if not hits_rows:
            hits_rows = '<tr><td colspan="5" class="muted">无规则命中</td></tr>'

        # 远端 IP 表行
        remote_rows = ""
        for r in remotes:
            risk = r.get("risk_hint") or ""
            remote_rows += f"""<tr>
              <td class="mono">{r.get('remote_ip', '')}</td>
              <td class="mono">{r.get('remote_port', '') or '-'}</td>
              <td>{r.get('protocol', '')}</td>
              <td class="mono">{r.get('conn_count', 0)}</td>
              <td>{risk}</td>
            </tr>"""

        # 连接明细表行
        conn_rows = ""
        for c in conns:
            conn_rows += f"""<tr>
              <td>{c.get('protocol', '')}</td>
              <td class="mono">{c.get('local_ip', '')}:{c.get('local_port', '')}</td>
              <td class="mono">{c.get('remote_ip', '') or '-'}:{c.get('remote_port', '') or '-'}</td>
              <td>{c.get('state', '') or '-'}</td>
            </tr>"""

        # Beaconing 统计
        beacon_html = ""
        if beacon:
            suspected_text = "是" if beacon.get("suspected") else "否"
            jitter_text = "是" if beacon.get("jitter_like") else "否"
            beacon_html = f"""<div class="section">
              <h3>Beaconing 检测结果</h3>
              <table class="info-table"><tbody>
                <tr><th>采样窗口</th><td>{beacon.get('sample_window', 0)}</td></tr>
                <tr><th>间隔均值</th><td>{beacon.get('interval_mean_ms', '-')} ms</td></tr>
                <tr><th>间隔标准差</th><td>{beacon.get('interval_std_ms', '-')} ms</td></tr>
                <tr><th>变异系数 CV</th><td>{beacon.get('interval_cv', '-')}</td></tr>
                <tr><th>疑似 Beaconing</th><td>{suspected_text}</td></tr>
                <tr><th>Jitter 特征</th><td>{jitter_text}</td></tr>
                <tr><th>备注</th><td>{beacon.get('notes', '-') or '-'}</td></tr>
              </tbody></table>
            </div>"""

        targets_html += f"""<div class="section">
          <h2>目标 #{i}：{proc.get('name', 'unknown')} (PID {proc.get('pid', '-')})</h2>

          <div class="kpi-row">
            <div class="kpi-item"><span class="kpi-label">风险等级</span><span class="badge {level_class}">{level}</span></div>
            <div class="kpi-item"><span class="kpi-label">总分</span><span class="kpi-value">{total}</span></div>
            <div class="kpi-item"><span class="kpi-label">进程维度</span><span>{score.get('process', 0)}</span></div>
            <div class="kpi-item"><span class="kpi-label">网络维度</span><span>{score.get('network', 0)}</span></div>
          </div>

          <div class="section">
            <h3>进程信息</h3>
            <table class="info-table"><tbody>
              <tr><th>PID</th><td>{proc.get('pid', '-')}</td></tr>
              <tr><th>名称</th><td>{proc.get('name', '-')}</td></tr>
              <tr><th>路径</th><td class="mono">{proc.get('exe_path', '-') or '-'}</td></tr>
              <tr><th>用户</th><td>{proc.get('username', '-') or '-'}</td></tr>
              <tr><th>签名状态</th><td>{proc.get('signed_status', '-')}</td></tr>
              <tr><th>系统进程</th><td>{'是' if proc.get('is_system') else '否'}</td></tr>
              <tr><th>可疑路径</th><td>{'是' if proc.get('path_suspicious') else '否'}</td></tr>
              <tr><th>异常父子关系</th><td>{'是' if proc.get('parent_child_suspicious') else '否'}</td></tr>
            </tbody></table>
          </div>

          <div class="section">
            <h3>规则命中</h3>
            <table class="data-table">
              <thead><tr><th>Rule ID</th><th>描述</th><th>维度</th><th>加分</th><th>证据</th></tr></thead>
              <tbody>{hits_rows}</tbody>
            </table>
          </div>

          {beacon_html}

          {_build_remote_section(remote_rows)}

          {_build_conn_section(conn_rows)}

          <div class="section">
            <h3>评分摘要</h3>
            <p>{score.get('summary_reason', '-') or '-'}</p>
          </div>
        </div>"""

    # KPI 卡片
    kpi_html = f"""<div class="kpi-row">
      <div class="kpi-item"><span class="kpi-label">扫描目标数</span><span class="kpi-value">{summary.get('target_count', 0)}</span></div>
      <div class="kpi-item"><span class="kpi-label">高风险</span><span class="kpi-value high">{summary.get('high_count', 0)}</span></div>
      <div class="kpi-item"><span class="kpi-label">中风险</span><span class="kpi-value mid">{summary.get('mid_count', 0)}</span></div>
      <div class="kpi-item"><span class="kpi-label">低风险</span><span class="kpi-value low">{summary.get('low_count', 0)}</span></div>
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>ProcRisk 扫描报告 - {meta.get('scan_id', '')}</title>
  <style>
    :root {{
      --primary: #0d9488; --primary-600: #0f766e;
      --low: #059669; --mid: #d97706; --high: #dc2626;
      --text: #0f2e1e; --muted: #64748b;
      --bg: #f0f9f4; --card: #ffffff; --border: #e4f7ee;
    }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; padding: 32px 24px; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    h1 {{ font-size: 24px; margin-bottom: 4px; }}
    h2 {{ font-size: 20px; margin-top: 0; border-bottom: 2px solid var(--border); padding-bottom: 8px; }}
    h3 {{ font-size: 16px; margin-top: 0; margin-bottom: 12px; color: var(--primary-600); }}
    .muted {{ color: var(--muted); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
    .small {{ font-size: 12px; }}
    .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
    .kpi-row {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
    .kpi-item {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 20px; display: flex; flex-direction: column; gap: 4px; min-width: 120px; }}
    .kpi-label {{ color: var(--muted); font-size: 12px; font-weight: 500; }}
    .kpi-value {{ font-size: 24px; font-weight: 700; }}
    .kpi-value.high {{ color: var(--high); }}
    .kpi-value.mid {{ color: var(--mid); }}
    .kpi-value.low {{ color: var(--low); }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }}
    .badge.low {{ color: var(--low); background: rgba(5,150,105,0.1); }}
    .badge.mid {{ color: var(--mid); background: rgba(217,119,6,0.1); }}
    .badge.high {{ color: var(--high); background: rgba(220,38,38,0.1); }}
    .info-table {{ width: 100%; border-collapse: collapse; }}
    .info-table th, .info-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); text-align: left; }}
    .info-table th {{ width: 140px; color: var(--muted); font-size: 13px; font-weight: 500; white-space: nowrap; }}
    .data-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    .data-table th, .data-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; }}
    .data-table thead th {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; background: rgba(13,148,136,0.04); }}
    .meta-row {{ display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; }}
    .meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
    .meta-label {{ font-size: 12px; color: var(--muted); }}
    .meta-value {{ font-size: 14px; font-weight: 500; }}
    .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; text-align: center; }}
    @media print {{ body {{ padding: 16px; background: #fff; }} .section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <div class="container">
    <h1>ProcRisk 扫描报告</h1>
    <p class="muted">基于 Beacon 行为特征的主机进程异常分析与风险评分系统</p>

    <div class="section">
      <div class="meta-row">
        <div class="meta-item"><span class="meta-label">Scan ID</span><span class="meta-value mono">{meta.get('scan_id', '-')}</span></div>
        <div class="meta-item"><span class="meta-label">扫描模式</span><span class="meta-value">{meta.get('mode', '-')}</span></div>
        <div class="meta-item"><span class="meta-label">扫描时间</span><span class="meta-value">{meta.get('created_at', '-')}</span></div>
        <div class="meta-item"><span class="meta-label">耗时</span><span class="meta-value">{meta.get('duration_ms', '-')} ms</span></div>
        <div class="meta-item"><span class="meta-label">主机</span><span class="meta-value">{meta.get('host_name', '-') or '-'}</span></div>
        <div class="meta-item"><span class="meta-label">系统</span><span class="meta-value">{meta.get('os_info', '-') or '-'}</span></div>
      </div>
    </div>

    {kpi_html}

    {targets_html}

    <div class="footer">
      ProcRisk v{meta.get('app_version', '0.1.0')} · 报告生成于 {meta.get('created_at', '-')}
    </div>
  </div>
</body>
</html>"""
