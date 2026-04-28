from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    # ---- 初始化数据库（SQLAlchemy + 自动建表） ----
    from webapp.db import init_db
    init_db(app)

    # ---- 蓝图注册（与 layout.html 的 url_for 保持一致） ----
    from webapp.views.main import main_bp
    from webapp.views.process_view import process_bp
    from webapp.views.scan_view import scan_bp
    from webapp.views.dashboard_view import dashboard_bp
    from webapp.views.export_view import export_bp
    from webapp.views.api import api_bp

    # 首页
    app.register_blueprint(main_bp)

    # 进程相关：/processes/
    app.register_blueprint(process_bp, url_prefix="/processes")

    # 扫描相关：/scans/
    app.register_blueprint(scan_bp, url_prefix="/scans")

    # 风险看板：/dashboard/
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    # 导出中心：/export/
    app.register_blueprint(export_bp, url_prefix="/export")

    # API：/api/
    app.register_blueprint(api_bp, url_prefix="/api")

    return app