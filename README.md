# ProcRisk

基于 Beacon 行为特征的主机进程异常分析与风险评分系统

---

## 项目简介

**s**系统通过多轮网络连接采样积累真实时间序列，利用变异系数（CV）算法检测周期性回连，并支持代理穿透还原被隐藏的真实 C2 地址。结合多维规则引擎对进程进行风险评分，输出 LOW / MID / HIGH 三级风险判定与完整证据链。

**核心特性**：

- **多轮采样 Beaconing 检测** — 12 轮 × 5 秒采样，CV 算法识别 C2 定时回连与 Jitter 特征
- **代理穿透** — 自动识别回环远端 IP，追踪代理进程还原真实 C2 地址
- **5 条多维检测规则** — 进程路径、父子关系、签名状态、命名模式、网络行为
- **智能过滤** — 进程列表默认排除系统进程与白名单，聚焦可疑目标
- **异步扫描** — 后台线程执行采样，前端实时展示进度条
- **报告导出** — JSON 数据 + 独立 HTML 报告，可打印归档

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        ProcRisk 系统流程                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ① 进程采集                                                      │
│  ┌──────────────────────────────────────┐                       │
│  │ psutil 两轮遍历本机进程                │                       │
│  │ → 打风险标签 (路径/父子/签名)          │                       │
│  │ → 写入 process_catalog 表             │                       │
│  └──────────────────┬───────────────────┘                       │
│                     ↓                                           │
│  ② 单进程检测                                                      │
│  ┌──────────────────────────────────────┐                       │
│  │ BeaconSampler 多轮采样                 │                       │
│  │ 12轮×5秒 → 采集连接快照               │                       │
│  │ → 检测 check-in 事件                  │                       │
│  │ → 检测持久连接                         │                       │
│  └──────────────────┬───────────────────┘                       │
│                     ↓                                           │
│  ③ 规则引擎检测                                                    │
│  ┌──────────────────────────────────────┐                       │
│  │ 白名单前置过滤                         │                       │
│  │ → PROC-001 异常父子关系               │                       │
│  │ → PROC-002 可疑路径                   │                       │
│  │ → PROC-003 未签名非系统进程           │                       │
│  │ → PROC-004 可疑进程名                 │                       │
│  │ → NET-101  Beaconing 通信 (注入)      │                       │
│  └──────────────────┬───────────────────┘                       │
│                     ↓                                           │
│  ④ 评分与输出                                                     │
│  ┌──────────────────────────────────────┐                       │
│  │ 维度加法评分 (0-100)                   │                       │
│  │ → LOW / MID / HIGH 分级              │                       │
│  │ → 远端IP汇总 (含代理穿透)             │                       │
│  │ → 写入数据库 + 展示 + 导出报告         │                       │
│  └──────────────────────────────────────┘                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 项目结构

```
beacon_proc_risk/
├── utils/                           # 核心检测逻辑
│   ├── common/                      # 通用工具
│   │   ├── constants.py             #   常量（可疑路径、父子映射、阈值）
│   │   ├── helpers.py               #   辅助函数
│   │   └── validators.py            #   验证器（白名单、可疑路径、系统路径）
│   ├── process_collector/           # 进程采集
│   │   ├── models.py                #   ProcessInfo 数据模型
│   │   ├── windows.py               #   psutil 采集 + 代理穿透
│   │   └── collector.py             #   统一接口 + DB 同步
│   ├── rule_engine/                 # 规则引擎
│   │   ├── context.py               #   RuleContext 上下文
│   │   ├── rules.py                 #   BaseRule + @register_rule + 5 条规则
│   │   └── engine.py                #   RuleEngine 核心
│   ├── risk_detector/               # 风险检测
│   │   ├── sampler.py               #   BeaconSampler 多轮采样器
│   │   ├── beacon.py                #   Beaconing 检测（CV + 持久连接 + 启发式）
│   │   ├── scorer.py                #   维度加法评分
│   │   └── detector.py              #   检测流水线编排
│   └── data_exporter/               # 数据导出
│       ├── json_export.py           #   嵌套 JSON 导出
│       ├── html_report.py           #   独立 HTML 报告
│       └── exporter.py              #   统一导出接口
├── webapp/                          # Flask Web 应用
│   ├── __init__.py                  # 应用工厂（7 个蓝图注册）
│   ├── db.py                        # 数据库初始化
│   ├── models.py                    # 10 张表 ORM 模型
│   ├── views/                       # 蓝图视图
│   │   ├── main.py                  #   首页
│   │   ├── process_view.py          #   进程列表（3 Tab 过滤）+ 详情
│   │   ├── scan_view.py             #   扫描中心 + 异步 API
│   │   ├── dashboard_view.py        #   风险看板
│   │   ├── allowlist_view.py        #   白名单管理
│   │   ├── export_view.py           #   报告导出
│   │   └── api.py                   #   批量扫描 + KPI
│   ├── templates/                   # Jinja2 模板（9 个）
│   └── static/css/main.css          # 薄荷绿主题样式
├── 项目文档/                         # 设计文档
├── app.py                           # 应用入口
├── config.py                        # 配置（含 Beaconing 采样参数）
├── requirements.txt                 # Python 依赖
├── docker-compose.yml               # Docker 编排（MySQL + phpMyAdmin）
└── .env                             # 环境变量（不入库）
```

---

## 快速开始

### 环境要求

- Python 3.10+
- Docker & Docker Compose（用于 MySQL）
- Windows 操作系统（进程采集依赖 psutil Windows API）

### 1. 克隆项目

```bash
git clone https://github.com/<your-username>/beacon_proc_risk.git
cd beacon_proc_risk
```

### 2. 启动 MySQL

```bash
docker compose up -d
```

这会启动：
- **MySQL 8.4** — 端口 `13306`，数据库名 `beacon_proc_risk`
- **phpMyAdmin** — 端口 `8081`（开发辅助，可选）

### 3. 配置环境变量

复制并编辑 `.env` 文件：

```bash
cp .env.example .env
```

`.env` 内容示例：

```ini
DB_HOST=127.0.0.1
DB_PORT=13306
DB_USER=your_mysql_user
DB_PASSWORD=your_password
DB_NAME=beacon_proc_risk
```

> 确保 `.env` 中的数据库配置与 `docker-compose.yml` 一致。

### 4. 安装依赖

```bash
pip install -r requirements.txt
```

主要依赖：

| 包 | 用途 |
|---|------|
| Flask ≥ 3.0 | Web 框架 |
| Flask-SQLAlchemy ≥ 3.1 | ORM |
| PyMySQL ≥ 1.1 | MySQL 驱动 |
| psutil ≥ 5.9 | 进程与系统信息采集 |
| python-dotenv ≥ 1.0 | 环境变量加载 |

### 5. 启动应用

```bash
python app.py
```

访问 http://localhost:5000 即可使用。

---

## 使用流程

### 全量进程采集

1. 在首页点击「扫描进程」按钮
2. 系统枚举本机所有运行进程，打风险标签，写入数据库
3. 完成后 Toast 提示进程数量与耗时，KPI 卡片自动刷新

### 单进程风险检测

1. 进入「进程列表」，默认显示"可疑"视图（已排除系统进程与白名单）
2. 点击目标进程进入详情页
3. 点击「扫描此进程」，系统启动异步多轮采样（12 轮 × 5 秒 = 60 秒）
4. 前端实时展示采样进度条
5. 采样完成后自动跳转扫描详情页，查看评分、规则命中、Beaconing 统计、远端 IP 汇总

### 白名单管理

- 在「白名单」页面添加/禁用/删除条目
- 在进程详情页可快速将进程按名称或路径加入白名单
- 白名单进程在列表和检测中自动跳过

### 报告导出

- 在「导出报告」页面选择扫描记录
- 导出 JSON（机器可读）或 HTML（可直接打印/保存 PDF）

---

## 检测规则

### 5 条内置规则

| 规则 ID | 名称 | 维度 | 权重 | 检测逻辑 |
|---------|------|------|------|----------|
| PROC-001 | 异常父子进程关系 | process | 20 | 父进程在可疑映射中且子进程匹配 |
| PROC-002 | 运行于可疑路径 | process | 30 | 路径匹配 9 种可疑模式且未签名 |
| PROC-003 | 未签名的非系统进程 | process | 15 | 签名状态非 signed 且非系统路径 |
| PROC-004 | 可疑进程名 | process | 20 | 匹配已知恶意命名或随机 8+ 位字母数字 .exe |
| NET-101 | 疑似 Beaconing 通信 | network | 35 | Beaconing 检测模块判定为疑似 |

### 可疑路径模式（9 种）

`\Temp\` `\AppData\Local\Temp\` `\Downloads\` `\Public\` `\Desktop\` `\AppData\Roaming\` `\ProgramData\` `\PerfLogs\` `\Recycle\`

### 可疑父子进程组合（6 组）

| 父进程 | 可疑子进程 |
|--------|-----------|
| svchost.exe | cmd, powershell, wscript, cscript |
| taskeng.exe | cmd, powershell |
| mshta.exe | cmd, powershell |
| winword.exe | cmd, powershell, wscript |
| excel.exe | cmd, powershell |
| outlook.exe | cmd, powershell |

---

## Beaconing 检测算法

### 多轮采样

单次 psutil 快照所有连接时间戳相同，无法计算间隔。`BeaconSampler` 以 5 秒间隔采集 12 轮连接快照，积累真实时间序列。

**关键概念**：

| 概念 | 定义 | 检测意义 |
|------|------|----------|
| Check-in | 某轮新出现的远端连接 | Beacon 每次回连 C2 |
| 持久连接 | ≥80% 采样轮次中持续存在的远端 | 长连接模式 Beacon |

### CV 检测

1. 从 check-in 时间序列计算相邻间隔
2. 计算均值 μ、标准差 σ、变异系数 CV = σ/μ
3. CV < 0.3 → 疑似 Beaconing；0.05 < CV < 0.15 → 含 Jitter 特征
4. 样本不足时：check-in 频率 ≥50% 采样轮次也标记为疑似

### 代理穿透

当远端 IP 为回环地址（127.0.0.1 等）时，自动查找监听该端口的代理进程，获取其真实远端连接，在结果中标注代理信息并替换为真实 IP。

### 参数配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `BEACON_SAMPLING_ENABLED` | True | 是否启用多轮采样 |
| `BEACON_SAMPLING_INTERVAL` | 5 | 采样间隔（秒） |
| `BEACON_SAMPLING_ROUNDS` | 12 | 采样轮数 |
| `BEACON_MIN_SAMPLES` | 10 | CV 计算最少样本数 |
| `BEACON_CV_THRESHOLD` | 0.3 | Beaconing 判定阈值 |
| `BEACON_JITTER_CV_MIN` | 0.05 | Jitter 检测下限 |

---

## 评分机制

**维度加法模型**：各规则 score_delta 按维度求和，总分上限 100。

| 等级 | 分数范围 | 含义 |
|------|---------|------|
| LOW | 0 - 39 | 无明显风险特征 |
| MID | 40 - 69 | 存在部分可疑特征 |
| HIGH | 70 - 100 | 多个高风险特征叠加 |

**典型评分示例**：

| 场景 | 命中规则 | 总分 | 等级 |
|------|---------|------|------|
| 系统进程 svchost.exe | 白名单命中，跳过检测 | 0 | LOW |
| CS Beacon artifact_x64.exe | PROC-002(30) + PROC-003(15) + PROC-004(20) + NET-101(35) | 100 | HIGH |
| 用户目录普通程序 | PROC-003(15) | 15 | LOW |

---

## 数据库

10 张 SQLAlchemy 表：

| 表 | 说明 |
|----|------|
| rules | 规则字典 |
| allowlist | 白名单 |
| scan_runs | 扫描任务 |
| process_catalog | 进程档案（含风险标签） |
| scan_targets | 扫描目标关联 |
| scan_scores | 评分汇总（1:1） |
| rule_hits | 规则命中记录（1:N） |
| net_beacon_stats | Beaconing 统计（1:1） |
| net_remote_summary | 远端 IP 汇总（1:N） |
| net_connections | 连接明细（1:N） |

首次启动时 SQLAlchemy 自动建表。

---

## MITRE ATT&CK 映射

| 规则 | ATT&CK 技术 | ID |
|------|-------------|-----|
| PROC-001 异常父子关系 | Command and Scripting Interpreter | T1059 |
| PROC-002 可疑路径 | Masquerading / User Execution | T1036 / T1204 |
| PROC-003 未签名非系统 | Signed Binary Proxy Execution | T1218 |
| PROC-004 可疑进程名 | Masquerading | T1036 |
| NET-101 Beaconing | Application Layer Protocol / C2 | T1071 / T1573 |

---

## 扩展指南

### 添加新检测规则

1. 在 `utils/rule_engine/rules.py` 中创建继承 `BaseRule` 的类
2. 添加 `@register_rule` 装饰器
3. 设置 `rule_id`、`title`、`dimension`、`default_weight`
4. 实现 `check(self, context: RuleContext) -> Optional[RuleHitResult]`
5. 规则引擎自动发现并加载，无需修改其他代码

### 添加白名单类型

1. 在 `webapp/models.py` 的 `Allowlist.type` Enum 中添加新值
2. 在 `utils/common/validators.py` 的 `is_allowed()` 中添加匹配逻辑
3. 执行 `ALTER TABLE allowlist MODIFY type ENUM(...)`

---

## 许可证

本项目为课程作业项目，仅供学习交流使用。
