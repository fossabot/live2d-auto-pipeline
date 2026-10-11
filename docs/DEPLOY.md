# 🚀 部署指南

> v0.10.5 起，项目全面转向**桌面应用**为唯一分发形态，直接利用本地 GPU/CPU 进行 AI 推理。
> Docker 和独立 Web 部署模式已废弃移除。

---

## 桌面安装（推荐）

### Windows 安装包

从 [Release 页面](https://github.com/mw2wbyys6t-sudo/live2d-auto-pipeline/releases) 下载最新的 `.exe` 安装包，双击即可安装。

安装包包含：
- Go API 二进制（内嵌前端 UI）
- 便携 Python 运行时
- AI 模型权重（SAM 等）
- 所有系统依赖（OpenCV、FFmpeg 等）

### 从源码构建桌面应用

```bash
# 1. 安装依赖
pip install -r requirements.txt
cd web && npm ci && cd ..
cd api && go mod download && cd ..

# 2. 一键构建桌面应用
# Windows:
scripts\build_desktop.bat
# Linux/macOS:
chmod +x scripts/build_desktop.sh && scripts/build_desktop.sh

# 3. 产物在 dist/ 目录
# dist/Live2DMasterAgent.exe        — 无控制台版本
# dist/Live2DMasterAgent-console.exe — 调试版本（带控制台输出）
```

构建流程：`NEXT_STATIC_EXPORT=1 npm run build` → 复制 `web/out/*` → `api/webui/dist/` → `go build`（内嵌 UI）

---

## 开发模式

开发时前后端分离运行，方便热更新调试：

```bash
# 终端 1 — Python 后端 + Go API
python api_server.py          # Python 服务（端口 8080）

# 终端 2 — Next.js 开发服务器
cd web && npm run dev         # 前端开发服务器（端口 3000）
```

开发模式下，Next.js 通过 `rewrites` 代理将 `/api/*`、`/output/*`、`/ws/*` 转发到后端 8080 端口，无需 CORS 配置。

---

## 环境变量

见 `.env.example`。关键配置：

| 变量 | 说明 | 默认 |
|------|------|------|
| GO_API_PORT | API 端口 | 8080 |
| OUTPUT_DIR | 输出目录 | ./output |
| ARK_API_KEY | 火山引擎 Key | 空 |
| OPENAI_API_KEY | OpenAI Key | 空 |
| REDIS_URL | Redis 连接 | 空(内存) |
