import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    STATE_FILE = os.path.join(BASE_DIR, "system_state.json")

    # 扫描相关（后面你可以写进报告：参数可配置）
    MAX_PROCESSES = 5000
    BEACON_SAMPLE_WINDOW = 20