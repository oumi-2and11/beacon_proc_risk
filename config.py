import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    STATE_FILE = os.path.join(BASE_DIR, "system_state.json")

    # 扫描相关（后面你可以写进报告：参数可配置）
    MAX_PROCESSES = 5000
    BEACON_SAMPLE_WINDOW = 20

    # ---- 数据库配置（从环境变量读取，不在代码中硬写密码） ----
    # 本地开发默认值对应 docker-compose.yml 中的 MySQL 容器
    DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT = os.environ.get("DB_PORT", "3306")
    DB_USER = os.environ.get("DB_USER", "oumi")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "CHANGE_ME_password")
    DB_NAME = os.environ.get("DB_NAME", "beacon_proc_risk")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False