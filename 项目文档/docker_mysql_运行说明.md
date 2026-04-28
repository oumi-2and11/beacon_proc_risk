# Docker MySQL 运行说明

> **适用场景**：Win11 本机运行 Flask 开发服务器，通过 Docker Desktop 启动 MySQL 容器提供数据库服务。
> Flask 应用直接连接 `127.0.0.1:3306`，无需把 Flask 也容器化。

---

## 目录

1. [前置条件](#一前置条件)
2. [配置环境变量](#二配置环境变量)
3. [启动 MySQL 容器](#三启动-mysql-容器)
4. [phpMyAdmin 管理界面（可选）](#四phpmyadmin-管理界面可选)
5. [安装 Python 依赖](#五安装-python-依赖)
6. [初始化数据库建表](#六初始化数据库建表)
7. [启动 Flask 开发服务器](#七启动-flask-开发服务器)
8. [常见问题](#八常见问题)

---

## 一、前置条件

| 工具 | 版本要求 | 说明 |
|------|---------|------|
| Docker Desktop | 最新稳定版 | Windows 下的 Docker 运行环境 |
| Python | 3.10+ | Flask 运行环境 |
| pip | 最新版 | Python 包管理 |

---

## 二、配置环境变量

项目使用 `.env` 文件注入密码等敏感信息，**该文件已加入 `.gitignore`，不会提交到 Git**。

### 步骤

```bash
# 在仓库根目录，复制模板
copy .env.example .env      # Windows CMD
# 或
cp .env.example .env        # PowerShell / Git Bash
```

然后用文本编辑器打开 `.env`，填入你的实际值：

```dotenv
MYSQL_ROOT_PASSWORD=你的root密码
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=oumi
DB_PASSWORD=你的应用密码
DB_NAME=beacon_proc_risk
SECRET_KEY=随机生成的密钥
```

> **生成随机密钥**：`python -c "import secrets; print(secrets.token_hex(32))"`

---

## 三、启动 MySQL 容器

在仓库根目录（含 `docker-compose.yml` 的目录）执行：

```bash
docker compose up -d
```

验证容器已启动：

```bash
docker compose ps
```

输出类似：

```
NAME                   IMAGE        STATUS
proc_risk_mysql        mysql:8.4    Up
proc_risk_phpmyadmin   phpmyadmin   Up
```

> **数据持久化**：MySQL 数据存储在 Docker volume `mysql_data` 中，`docker compose down` 不会删除数据；
> 如需彻底清空，使用 `docker compose down -v`。

---

## 四、phpMyAdmin 管理界面（可选）

`docker-compose.yml` 中包含了 phpMyAdmin 服务（端口 `8081`）。

**phpMyAdmin 是什么？**  
一个基于 Web 的 MySQL 图形化管理工具，无需安装客户端软件，在浏览器里就能查看/编辑数据库表、执行 SQL、管理用户。  
**为什么加它？** 课程报告截图方便（直接截表结构和数据），也方便快速验证 Flask 写入是否成功。

**登录方式：**

1. 打开浏览器，访问：`http://127.0.0.1:8081`
2. 服务器：`mysql`（phpMyAdmin 容器内部地址）
3. 用户名：`oumi`（或 `root`）
4. 密码：你在 `.env` 中设置的对应密码（**不要在文档里写死密码**）

---

## 五、安装 Python 依赖

```bash
# 建议在虚拟环境中操作
python -m venv venv
venv\Scripts\activate     # Windows
# source venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
```

`requirements.txt` 中包含：
- `Flask` — Web 框架
- `Flask-SQLAlchemy` — Flask 的 SQLAlchemy 集成
- `SQLAlchemy` — Python ORM / 数据库工具库
- `PyMySQL` — Python 连接 MySQL 的驱动
- `cryptography` — PyMySQL 加密连接支持

---

## 六、初始化数据库建表

Flask 应用在**第一次启动时自动建表**（通过 `db.create_all()`），无需手动执行 SQL。

如果你想提前验证连接是否正常，可以运行：

```bash
python -c "
from webapp import create_app
app = create_app()
print('数据库连接并建表成功！')
"
```

如果数据库连接失败，会看到类似 `OperationalError: Can't connect to MySQL server` 的报错，请检查：
- `.env` 中的密码是否正确
- MySQL 容器是否已启动（`docker compose ps`）
- 防火墙是否阻止了 3306 端口

---

## 七、启动 Flask 开发服务器

```bash
python app.py
```

成功后终端显示：

```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

打开浏览器访问 `http://127.0.0.1:5000`，进入首页。

**主要功能入口：**

| 路径 | 说明 |
|------|------|
| `/` | 首页 |
| `/processes/` | 进程列表，点击进程可跳转详情 |
| `/processes/<pid>` | 进程详情，可点击"扫描此进程"写入数据库 |
| `/scans/` | 扫描中心，列出所有历史扫描记录（从数据库读取） |
| `/dashboard/` | 风险看板，展示统计数据 |
| `/export/` | 导出中心 |
| `/api/health` | API 健康检查 |

---

## 八、常见问题

**Q：`docker compose up -d` 报错 "cannot find .env"**  
A：确认已在仓库根目录创建 `.env` 文件（参考 `.env.example`）。

**Q：Flask 启动时报 `OperationalError: (pymysql.err.OperationalError) (1045, "Access denied")`**  
A：`.env` 中 `DB_PASSWORD` 与 `docker-compose.yml` 中 `MYSQL_PASSWORD` 使用的 `DB_PASSWORD` 变量不一致，检查两处是否相同。

**Q：MySQL 容器首次启动较慢，Flask 连接超时**  
A：MySQL 8 首次初始化需要约 30-60 秒。等容器 status 变为 `healthy` 后再启动 Flask。

**Q：重启电脑后扫描数据还在吗？**  
A：在，数据存储在 Docker volume `mysql_data` 中，只要不执行 `docker compose down -v`，数据就不会丢失。

**Q：如何停止 MySQL 容器**  
A：`docker compose stop`（保留数据）或 `docker compose down`（停止+删除容器，保留 volume）。
