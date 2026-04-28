from webapp import create_app

# 下面两行自动读取项目根目录的 .env
from dotenv import load_dotenv
load_dotenv()

app = create_app()

if __name__ == "__main__":
    # Win11 本机开发：debug=True 方便热更新
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)