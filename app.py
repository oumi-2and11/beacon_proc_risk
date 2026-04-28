from webapp import create_app

app = create_app()

if __name__ == "__main__":
    # Win11 本机开发：debug=True 方便热更新
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)