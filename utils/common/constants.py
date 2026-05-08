"""全局常量定义，与数据库模型 enum 及模板逻辑对齐。"""

# 风险阈值：LOW < 40, MID 40-69, HIGH >= 70
RISK_THRESHOLD_MID = 40
RISK_THRESHOLD_HIGH = 70

RISK_LEVELS = ("LOW", "MID", "HIGH")

# 检测维度（匹配 DB enum）
DIMENSIONS = ("process", "network", "memory", "other")

# 签名状态（匹配 DB enum）
SIGNED_STATUS = ("unknown", "signed", "unsigned", "invalid")

# Windows 系统路径（用于判断 is_system）
WINDOWS_SYSTEM_PATHS = (
    "C:\\Windows\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
)

# 可疑路径模式
SUSPICIOUS_PATH_PATTERNS = (
    "\\Temp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Downloads\\",
    "\\Public\\",
)

# 可疑父-子进程关系映射（key=父进程名, value=可疑子进程列表）
SUSPICIOUS_PARENT_CHILD = {
    "svchost.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "taskeng.exe": ["cmd.exe", "powershell.exe"],
    "mshta.exe": ["cmd.exe", "powershell.exe"],
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
}

# Beaconing 检测阈值
BEACON_MIN_SAMPLES = 10
BEACON_CV_THRESHOLD = 0.3
BEACON_JITTER_CV_MIN = 0.05

APP_VERSION = "0.1.0"
