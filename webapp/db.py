"""
webapp/db.py
SQLAlchemy 实例与初始化辅助函数。
"""
from flask_sqlalchemy import SQLAlchemy

# 全局 SQLAlchemy 实例，由 create_app() 调用 init_db() 完成绑定
db = SQLAlchemy()


def init_db(app):
    """将 SQLAlchemy 绑定到 Flask app，并自动建表（如果表不存在）。"""
    db.init_app(app)
    with app.app_context():
        # 导入所有模型以确保它们在 create_all() 前已注册
        from webapp import models  # noqa: F401
        db.create_all()
